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
package zeroecho.pki.impl.crypto.zeroecholib;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.KeyUsage;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.alg.common.sig.SignatureInteropProfile;
import zeroecho.core.alg.common.sig.SignatureInteropProfiles;
import zeroecho.core.alg.ecdsa.EcdsaPublicKeySpec;
import zeroecho.core.alg.ed25519.Ed25519PublicKeySpec;
import zeroecho.core.alg.ed448.Ed448PublicKeySpec;
import zeroecho.core.alg.mldsa.MldsaPublicKeySpec;
import zeroecho.core.alg.rsa.RsaPublicKeySpec;
import zeroecho.core.alg.slhdsa.SlhDsaPublicKeySpec;
import zeroecho.core.alg.sphincsplus.SphincsPlusPublicKeySpec;
import zeroecho.core.context.SignatureContext;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringSignatureExecutor;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.fs.LocalExecutionPermit;
import zeroecho.pki.spi.crypto.LocalSigningLedgerParticipant;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.sdk.ZeroEchoSession;

/**
 * ZeroEcho-lib backed implementation of {@link SignatureWorkflow}.
 *
 * <p>
 * This provider forms a cryptographic boundary between the PKI orchestration
 * layer and ZeroEcho-lib based key material handling backed by
 * {@link KeyringStore}. It resolves opaque {@link KeyRef} values to provider-
 * local keyring aliases, delegates signing to the keyring-owned execution
 * boundary, and performs verification through the explicit
 * {@link ZeroEchoSession} and {@link SignatureContext}. Private key objects never
 * enter this PKI module.
 * </p>
 *
 * <p>
 * The implementation is intentionally synchronous from its internal execution
 * perspective, but it still conforms to the {@link SignatureWorkflow} contract
 * by returning an operation identifier and exposing the terminal outcome
 * through {@link #status(PkiId, CallControl)}. Each submitted operation is executed
 * immediately in the caller thread. For the built-in production path, the
 * filesystem store owns the shared signing ledger and lends this workflow a
 * narrow process-local participant for atomic acceptance and completion.
 * </p>
 *
 * <h2>Supported operations</h2>
 * <ul>
 * <li>{@link #submitSign(SignRequest, CallControl)} resolves a private key from the configured
 * {@link KeyringStore}, validates the requested algorithm
 * compatibility, produces a signature over the supplied payload, and stores the
 * result as a terminal successful or failed operation status.</li>
 * <li>{@link #submitVerify(VerifyRequest, CallControl)} verifies a signature either against
 * a key resolved from {@link VerifyRequest#publicKeyRef()} or against a caller-
 * supplied encoded public key from
 * {@link VerifyRequest#publicKeyEncoded()}.</li>
 * <li>{@link #status(PkiId, CallControl)} returns the retained operation status, or a stable
 * failed status for unknown operation identifiers.</li>
 * <li>{@link #register(NotificationSink)} installs an in-memory notification
 * sink that is called whenever an operation status changes.</li>
 * </ul>
 *
 * <h2>Signing lifecycle and recovery</h2>
 * <p>
 * A repeated signing submission with the same stable identifier and semantic
 * fingerprint attaches to the retained operation and does not repeat
 * cryptographic work. Conflicting fingerprints and stale fencing tokens fail
 * closed. During store recovery, retained terminal operations remain queryable,
 * while an interrupted active local operation is durably converted to
 * {@link State#FAILED} with detail {@code RECOVERY_INCOMPLETE}; cryptographic
 * execution is never replayed implicitly. Signing records are purged after the
 * configured horizon, after which their stable identifiers report
 * {@link State#EXPIRED}. Only notification registrations are memory-only and
 * must be re-established after restart.
 * </p>
 *
 * <h2>Failure model</h2>
 * <p>
 * Validation failures, policy mismatches, lookup problems, and cryptographic
 * execution failures must not escape the public workflow boundary as uncaught
 * exceptions once an operation has been accepted for processing. Instead, the
 * provider always returns an operation identifier and records a terminal
 * {@link State#FAILED} status with a stable non-secret detail code retrievable
 * through {@link #status(PkiId, CallControl)}.
 * </p>
 *
 * <p>
 * Only direct caller contract violations detected before operation execution
 * starts, such as {@code null} request objects or blank mandatory scalar
 * parameters in public methods, are surfaced as immediate argument exceptions.
 * </p>
 *
 * <h2>Key reference handling</h2>
 * <p>
 * {@link KeyRef} values are treated as opaque by PKI callers, but this provider
 * applies a provider-specific internal mapping to derive keyring aliases. The
 * mapping is controlled by the configured {@code keyRefPrefix} and by the
 * {@code requireComponentSuffix} flag.
 * </p>
 *
 * <p>
 * In the default deployment style:
 * </p>
 * <ul>
 * <li>signing expects a logical private component such as
 * {@code zeroecho-lib:&lt;alias&gt;.prv},</li>
 * <li>verification by key reference expects a logical public component such as
 * {@code zeroecho-lib:&lt;alias&gt;.pub}.</li>
 * </ul>
 *
 * <h2>Algorithm handling</h2>
 * <p>
 * Signing resolves requested identifiers through
 * {@link BootstrapAlgorithmIdentities} and delegates the exact canonical identity
 * to the keyring-owned executor. Verification retains compatibility normalization
 * for supported public-key import forms. For interoperable algorithms, the
 * provider transparently maps between external signature form and the internal
 * ZeroEcho representation expected by {@link SignatureContext}.
 * </p>
 *
 * <h2>Persistence and lifecycle</h2>
 * <ul>
 * <li>Signing request identity, fencing token, request snapshot, status, and
 * signature result are stored in the store-owned segmented ledger until the configured horizon.
 * Exact submissions attach to these records after restart.</li>
 * <li>An active local signing record found during store recovery is changed
 * durably to {@link State#FAILED} with detail {@code RECOVERY_INCOMPLETE};
 * signing is not replayed.</li>
 * <li>Verification statuses and notification registrations are memory-only and
 * are lost when the provider is closed or the process restarts.</li>
 * <li>The underlying {@link KeyringStore} is loaded lazily on first use and
 * then cached in the provider instance.</li>
 * <li>{@link #close()} clears memory-resident caches and registrations and closes
 * keyring resources. The store retains ownership of durable signing records.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Never logs {@link KeyRef} values.</li>
 * <li>Never logs payload bytes or signature bytes.</li>
 * <li>Never returns private key material; signing key resolution occurs only in
 * the keyring-owning library boundary.</li>
 * <li>Notification sinks must be treated as trusted local integration points,
 * because they receive operation identifiers and status metadata for all
 * operations observed by this provider instance.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Concurrent registries and lifecycle-bounded per-operation locks protect
 * mutable state. Cryptographic work and notification callbacks run without an
 * operation lock held, so unrelated operation identifiers can progress
 * independently. Callbacks are invoked inline after durable status changes and
 * may therefore affect caller latency, but callback failures are isolated.
 * </p>
 */
// The provider deliberately centralizes operation lifecycle and cleanup in one implementation.
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.ExceptionAsFlowControl",
        "PMD.AvoidCatchingGenericException", "PMD.TooManyMethods", "PMD.CouplingBetweenObjects" })
public final class ZeroEchoLibSignatureWorkflow implements SignatureWorkflow, PublicKeyInfoSource {

    private static final Logger LOG = Logger.getLogger(ZeroEchoLibSignatureWorkflow.class.getName());

    // Stable detail codes (non-secret), intended for audit + transport mapping.
    /** Operation was durably submitted. */
    public static final String DC_SUBMITTED = "SUBMITTED";
    /** Signature completed successfully. */
    public static final String DC_SIGNED = "SIGNED";
    /** Verification completed successfully. */
    public static final String DC_VERIFIED = "VERIFIED";
    /** Provider policy rejected the request. */
    public static final String DC_REJECTED = "REJECTED";
    /** Provider confirmed cancellation. */
    public static final String DC_CANCELLED = "CANCELLED";

    /** Managed-key reference has an invalid component suffix. */
    public static final String DC_INVALID_KEYREF_SUFFIX = "INVALID_KEYREF_SUFFIX";
    /** Managed-key reference is outside this provider's namespace. */
    public static final String DC_INVALID_KEYREF_PREFIX = "INVALID_KEYREF_PREFIX";
    /** Public-key representation is unsupported. */
    @SuppressWarnings("PMD.LongVariable")
    public static final String DC_UNSUPPORTED_PUBLICKEY_FORM = "UNSUPPORTED_PUBLICKEY_FORM";
    /** Signature algorithm identifier is malformed or unknown. */
    public static final String DC_INVALID_ALGORITHM_ID = "INVALID_ALGORITHM_ID";
    /** Requested algorithm does not match the managed key. */
    public static final String DC_ALGORITHM_MISMATCH = "ALGORITHM_MISMATCH";
    /** Keyring storage could not be read or updated. */
    public static final String DC_KEYRING_IO_ERROR = "KEYRING_IO_ERROR";
    /** Referenced managed key does not exist. */
    public static final String DC_KEY_NOT_FOUND = "KEY_NOT_FOUND";
    /** Cryptographic operation failed. */
    public static final String DC_CRYPTO_FAILURE = "CRYPTO_FAILURE";
    /** Repeatable content failed its integrity commitment. */
    public static final String DC_CONTENT_INTEGRITY_FAILURE = "CONTENT_INTEGRITY_FAILURE";
    /** Requested signature encoding is unsupported. */
    @SuppressWarnings("PMD.LongVariable")
    public static final String DC_UNSUPPORTED_SIGNATURE_ENCODING = "UNSUPPORTED_SIGNATURE_ENCODING";
    /** Operation identifier is unknown to this provider. */
    public static final String DC_UNKNOWN_OPERATION = "UNKNOWN_OPERATION";

    private static final OperationStatus UNKNOWN_OPERATION_STATUS = new OperationStatus(State.FAILED, Instant.EPOCH,
            Optional.of(DC_UNKNOWN_OPERATION), Optional.empty());
    private static final long MIN_FENCING_TOKEN = 1L;

    private final String id;
    private final Path keyringPath;
    private final Clock clock;
    private final Duration operationHorizon;
    private final String keyRefPrefix;
    private final boolean requireComponentSuffix;
    private final ConfigurationCommitment configurationCommitment;
    private final ZeroEchoSession session;
    private final KeyringUnlockProvider keyringUnlockProvider;

    private final ConcurrentMap<PkiId, OperationStatus> statuses;
    private final ConcurrentMap<PkiId, String> fingerprints;
    private final ConcurrentMap<PkiId, Long> fences;
    private final ConcurrentMap<PkiId, String> cancellationReasons;
    private final ConcurrentMap<PkiId, SignRequest> requests;
    private final ConcurrentMap<PkiId, NotificationSink> sinks;
    private final ConcurrentMap<PkiId, SignLockEntry> operationLocks;
    private final AtomicLong timeWatermark;
    private final ReentrantLock timeWatermarkLock;
    private final AtomicReference<String> boundNamespace;
    private final ReentrantLock domainLock;
    private final ReentrantLock keyringLifecycleLock;
    private final BiConsumer<String, byte[]> cleanupObserver;
    private final LocalSigningLedgerParticipant localLedger;

    private volatile KeyringStore keyringOrNull; // NOPMD
    private boolean closed;

    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, ConfigurationCommitment configurationCommitment) {
        this(id, keyringPath, standaloneScope, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, (category, cleared) -> {
                }, new ZeroEchoSession(), configurationCommitment);
    }

    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, KeyringStore keyring) {
        this(id, keyringPath, standaloneScope, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, configurationCommitment(keyring, id, operationHorizon, keyRefPrefix,
                        requireComponentSuffix));
        this.keyringOrNull = Objects.requireNonNull(keyring, "keyring must not be null");
    }

    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, SigningDependencies signingDependencies) {
        this(id, keyringPath, standaloneScope, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, (category, cleared) -> {
                }, signingDependencies.session(), configurationCommitment(signingDependencies.keyring(), id,
                        operationHorizon, keyRefPrefix, requireComponentSuffix));
        this.keyringOrNull = signingDependencies.keyring();
    }

    @SuppressWarnings("PMD.ExcessiveParameterList")
    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, BiConsumer<String, byte[]> cleanupObserver,
            ConfigurationCommitment configurationCommitment) {
        this(id, keyringPath, standaloneScope, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, cleanupObserver, new ZeroEchoSession(), configurationCommitment);
    }

    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, KeyringStore keyring,
            LocalSigningLedgerParticipant localLedger) {
        this(id, keyringPath, null, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, (category, cleared) -> {
                }, new ZeroEchoSession(), localLedger, configurationCommitment(keyring, id, operationHorizon,
                        keyRefPrefix, requireComponentSuffix));
        this.keyringOrNull = Objects.requireNonNull(keyring, "keyring must not be null");
    }

    private ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, BiConsumer<String, byte[]> cleanupObserver,
            ZeroEchoSession session, ConfigurationCommitment configurationCommitment) {
        this(id, keyringPath, standaloneScope, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, cleanupObserver, session, null, configurationCommitment);
    }

    private ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, BiConsumer<String, byte[]> cleanupObserver,
            ZeroEchoSession session, LocalSigningLedgerParticipant localLedger,
            ConfigurationCommitment configurationCommitment) {
        Objects.requireNonNull(standaloneScope == null && localLedger != null ? keyringPath : standaloneScope,
                "standaloneScope must not be null for a standalone test workflow");
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (keyringPath == null) {
            throw new IllegalArgumentException("keyringPath must not be null");
        }
        if (clock == null) {
            throw new IllegalArgumentException("clock must not be null");
        }
        if (operationHorizon == null || operationHorizon.isZero() || operationHorizon.isNegative()) {
            throw new IllegalArgumentException("operationHorizon must be positive");
        }
        if (keyRefPrefix == null) {
            throw new IllegalArgumentException("keyRefPrefix must not be null");
        }
        if (cleanupObserver == null) {
            throw new IllegalArgumentException("cleanupObserver must not be null");
        }
        if (keyringUnlockProvider == null) {
            throw new IllegalArgumentException("keyringUnlockProvider must not be null");
        }
        this.id = id;
        this.keyringPath = keyringPath;
        this.clock = clock;
        this.operationHorizon = operationHorizon;
        this.keyRefPrefix = keyRefPrefix;
        this.requireComponentSuffix = requireComponentSuffix;
        this.configurationCommitment = Objects.requireNonNull(configurationCommitment,
                "configurationCommitment must not be null");
        this.cleanupObserver = cleanupObserver;
        this.keyringUnlockProvider = keyringUnlockProvider;
        this.session = Objects.requireNonNull(session, "session must not be null");
        this.localLedger = localLedger;

        this.statuses = new ConcurrentHashMap<>();
        this.fingerprints = new ConcurrentHashMap<>();
        this.fences = new ConcurrentHashMap<>();
        this.cancellationReasons = new ConcurrentHashMap<>();
        this.requests = new ConcurrentHashMap<>();
        this.sinks = new ConcurrentHashMap<>();
        this.operationLocks = new ConcurrentHashMap<>();
        this.domainLock = new ReentrantLock();
        this.keyringLifecycleLock = new ReentrantLock();
        this.timeWatermarkLock = new ReentrantLock();
        this.timeWatermark = new AtomicLong(0L);
        this.boundNamespace = new AtomicReference<>(localLedger == null ? null
                : localLedger.localSigningNamespace(id));
    }

    @Override
    public String id() {
        return this.id;
    }

    @Override
    public ConfigurationCommitment configurationCommitment() {
        return configurationCommitment;
    }

    // Commitment failures are redacted at this provider boundary.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static ConfigurationCommitment configurationCommitment(KeyringStore keyring, String id,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix) {
        Objects.requireNonNull(keyring, "keyring must not be null");
        byte[] tag = null;
        try {
            tag = keyring.zeroEchoSigningConfigurationTag(id, operationHorizon, keyRefPrefix,
                    requireComponentSuffix);
            return new ConfigurationCommitment(tag);
        } catch (GeneralSecurityException exception) {
            throw new IllegalStateException("ZEROECHO_SIGNING_CONFIGURATION_COMMITMENT_FAILED");
        } finally {
            if (tag != null) {
                Arrays.fill(tag, (byte) 0);
            }
        }
    }

    @Override
    public void validateSigningDomain(String namespace, Duration horizon, Duration permittedSkew) {
        if (namespace == null || !namespace.endsWith("." + id) || !operationHorizon.equals(horizon)
                || !Duration.ZERO.equals(permittedSkew)) {
            throw new IllegalArgumentException("ZeroEchoLib signing domain mismatch");
        }
        if (localLedger != null) {
            if (!namespace.equals(localLedger.localSigningNamespace(id))
                    || !horizon.equals(localLedger.signingHorizon())) {
                throw new IllegalArgumentException("ZeroEchoLib signing domain mismatch");
            }
            return;
        }
        domainLock.lock();
        try {
            String current = boundNamespace.get();
            if (current != null && !current.equals(namespace)) {
                throw new IllegalArgumentException("ZeroEchoLib workflow belongs to a different signing domain");
            }
            if (current == null) {
                boundNamespace.set(namespace);
            }
        } finally {
            domainLock.unlock();
        }
    }

    /**
     * Returns the set of signature algorithm identifiers known to this provider.
     *
     * <p>
     * The result is informational. Presence of an algorithm identifier in the
     * returned set does not guarantee that a corresponding key is available, that
     * current runtime policy permits its use, or that a particular request will be
     * accepted.
     * </p>
     *
     * @return immutable set of supported or recognized signature algorithm
     *         identifiers
     */
    @Override
    public Set<String> supportedAlgorithms() {
        // Informational only; runtime policy/key availability may still reject.
        Set<String> supported = new java.util.LinkedHashSet<>(session.available());
        supported.addAll(SignatureInteropProfiles.algorithmIds());
        return Collections.unmodifiableSet(supported);
    }

    /**
     * Submits a signing operation and returns its workflow operation identifier.
     *
     * <p>
     * The operation is executed immediately in the caller thread. The returned
     * {@link PkiId} is the stable lookup identifier through which callers can
     * query the resulting terminal {@link OperationStatus}; it carries no live
     * workflow context.
     * </p>
     *
     * <p>
     * The method validates the key reference, resolves the requested algorithm to
     * an exact canonical identity, delegates key resolution and streaming signature
     * generation to {@link KeyringSignatureExecutor}, encodes the resulting
     * signature according to the preferred output encoding, and stores the final
     * outcome in the internal status registry.
     * </p>
     *
     * <p>
     * Validation and runtime failures are converted to terminal
     * {@link State#FAILED} statuses with stable detail codes rather than being
     * exposed directly to workflow callers.
     * </p>
     *
     * @param request sign request; must not be {@code null}
     * @return operation identifier that can be used to query the terminal result
     * @throws IllegalArgumentException if {@code request} is {@code null}
    */
    @Override
    public PkiId submitSign(SignRequest request, CallControl control) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        Objects.requireNonNull(control, "control").requireActive(now());
        requireMatchingConfiguration(request);

        PkiId opId = request.submissionId();
        if (!request.namespace().endsWith("." + id)) {
            throw new IllegalArgumentException("Signing request namespace mismatch");
        }
        validateSigningDomain(request.namespace(), operationHorizon, Duration.ZERO);
        SigningSubmissionId parsed = SigningSubmissionId.parse(opId);
        purgeExpiredOperations();
        parsed.validate(request.namespace(), now(), operationHorizon, Duration.ZERO);
        if (localLedger != null) {
            LocalSigningLedgerParticipant.Acceptance acceptance = localLedger.acceptLocalSign(request);
            if (acceptance == LocalSigningLedgerParticipant.Acceptance.ATTACHED) {
                return opId;
            }
        } else if (!beginSign(request, control)) {
            return opId;
        }

        return executeAcceptedRequest(request, control);
    }

    /**
     * Consumes the one-shot authority for an atomically admitted local request.
     *
     * @param request exact durably admitted request
     * @param permit one-shot authority minted by the admitting participant
     * @param control invocation deadline and cancellation control
     * @return the admitted operation identifier
     */
    public PkiId submitAcceptedLocalSign(SignRequest request, LocalExecutionPermit permit, CallControl control) {
        try (LocalTerminalCompletion completion = prepareAcceptedLocalSign(request, permit, control)) {
            return completion.commit();
        }
    }

    /**
     * Executes accepted local cryptography once and transfers its terminal result
     * to a short-lived, explicitly clearable persistence owner.
     *
     * @param request exact durably admitted request
     * @param permit one-shot authority minted by the admitting participant
     * @param control invocation deadline and cancellation control
     * @return terminal persistence owner
     */
    public LocalTerminalCompletion prepareAcceptedLocalSign(SignRequest request,
            LocalExecutionPermit permit, CallControl control) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(control, "control").requireActive(now());
        requireMatchingConfiguration(request);
        if (localLedger == null) {
            throw new IllegalStateException("Local signing ledger is unavailable");
        }
        Optional<CancellationSignal> storeCancellation = Objects.requireNonNull(permit, "permit")
                .consume(localLedger, request, configurationCommitment);
        if (storeCancellation.isEmpty()) {
            return new LocalTerminalCompletion(request.submissionId(), null, null, null, null);
        }
        if (request.cancellation().isCancelled() || storeCancellation.orElseThrow().isCancelled()) {
            OperationStatus cancelled = new OperationStatus(State.CANCELLED, now(), Optional.of(DC_CANCELLED),
                    Optional.empty());
            return new LocalTerminalCompletion(request.submissionId(), request, cancelled, null, null);
        }
        return prepareAcceptedRequest(request, control, storeCancellation.orElseThrow());
    }

    private PkiId executeAcceptedRequest(SignRequest request, CallControl control) {
        CancellationSignal storeCancellation = localLedger == null
                ? CancellationSignal.NONE : localLedger.localCancellation(request.submissionId());
        return executeAcceptedRequest(request, control, storeCancellation);
    }

    private PkiId executeAcceptedRequest(SignRequest request, CallControl control,
            CancellationSignal storeCancellation) {
        try (LocalTerminalCompletion completion = prepareAcceptedRequest(request, control, storeCancellation)) {
            return completion.commit();
        }
    }

    @SuppressWarnings("PMD.UseTryWithResources") // Ownership transfers into LocalTerminalCompletion on success.
    private LocalTerminalCompletion prepareAcceptedRequest(SignRequest request, CallControl control,
            CancellationSignal storeCancellation) {
        PkiId opId = request.submissionId();
        SignExecutionResult execution = null;
        try {
            CancellationSignal sharedCancellation = localLedger == null
                    ? request.cancellation() : () -> request.cancellation().isCancelled()
                            || storeCancellation.isCancelled();
            SignRequest executing = withCancellation(request, sharedCancellation);
            execution = executeAcceptedSign(executing, control);
            Instant commitTime = now();
            control.requireActive(commitTime);
            if (localLedger != null) {
                return new LocalTerminalCompletion(opId, request, execution, null);
            } else {
                completeSign(request, execution.status());
                return new LocalTerminalCompletion(opId, null, null, null, null);
            }
        } catch (RuntimeException failure) {
            Instant stoppedAt = now();
            if (callStopped(request, control, stoppedAt)) {
                OperationStatus stopped = stoppedSignStatus(request, control, stoppedAt);
                if (localLedger != null) {
                    return new LocalTerminalCompletion(opId, request, stopped, failure, null);
                } else {
                    completeSign(request, stopped);
                }
            }
            throw failure;
        } finally {
            if (execution != null) {
                execution.close();
            }
        }
    }

    private static SignRequest withCancellation(SignRequest request, CancellationSignal cancellation) {
        return new SignRequest(request.submissionId(), request.namespace(), request.semanticFingerprint(),
                request.configurationCommitment(), request.fencingToken(), request.accessContext(), request.keyRef(),
                request.algorithmId(),
                request.contentCommitment(), request.content(), request.preferredSignatureEncoding(),
                request.deadline(), cancellation);
    }

    private void requireMatchingConfiguration(SignRequest request) {
        if (!configurationCommitment.matches(request.configurationCommitment())) {
            throw new IllegalArgumentException("Signing request configuration commitment mismatch");
        }
    }

    private static boolean callStopped(SignRequest request, CallControl control, Instant observedAt) {
        return request.cancellation().isCancelled() || control.cancellation().isCancelled()
                || !observedAt.isBefore(control.deadline()) || deadlineReached(request.deadline(), observedAt);
    }

    private static OperationStatus stoppedSignStatus(SignRequest request, CallControl control, Instant observedAt) {
        boolean cancelled = request.cancellation().isCancelled() || control.cancellation().isCancelled();
        return cancelled
                ? new OperationStatus(State.CANCELLED, observedAt, Optional.of(DC_CANCELLED), Optional.empty())
                : expiredStatus(observedAt);
    }

    @SuppressWarnings({ "PMD.CloseResource", "PMD.CompareObjectsWithEquals",
            "PMD.UseTryWithResources" })
    // The final encoded array is deliberately moved between exclusive owners.
    private SignExecutionResult executeAcceptedSign(SignRequest request, CallControl control) {
        byte[] signatureBytes = null;
        OwnedEncodedSignature encodedSignature = null;
        try {
            KeyRefParts parts = parseKeyRefOrThrow(request.keyRef(), true);

            if (request.algorithmId() == null || request.algorithmId().isBlank()) {
                throw new InvalidRequestException(DC_INVALID_ALGORITHM_ID);
            }
            Optional<AlgorithmIdentity> resolvedAlgorithm = BootstrapAlgorithmIdentities.resolve(request.algorithmId());
            if (resolvedAlgorithm.isEmpty()
                    || resolvedAlgorithm.get().kind() != AlgorithmIdentity.Kind.SIGNATURE) {
                throw new InvalidRequestException(DC_INVALID_ALGORITHM_ID);
            }

            control.requireActive(now());
            if (deadlineReached(request.deadline(), now())) {
                return new SignExecutionResult(expiredStatus());
            }
            KeyringSignatureExecutor executor = requireSignatureExecutor();
            try (CommittedContent committedContent = new CommittedContent(request.content(),
                    request.contentCommitment())) {
                signatureBytes = executor.sign(parts.privateAlias, resolvedAlgorithm.get(), committedContent,
                        () -> request.cancellation().isCancelled() || control.cancellation().isCancelled()
                                || !now().isBefore(control.deadline()));
            }

            control.requireActive(now());
            Encoding outEnc = request.preferredSignatureEncoding().orElse(Encoding.BINARY);
            encodedSignature = encodeSignatureForTransfer(outEnc, signatureBytes);
            if (encodedSignature.bytes == signatureBytes) {
                signatureBytes = null;
            }

            Instant completedAt = now();
            if (deadlineReached(request.deadline(), completedAt)) {
                return new SignExecutionResult(expiredStatus(completedAt));
            }
            SignExecutionResult result = new SignExecutionResult(completedAt, encodedSignature);
            encodedSignature = null;
            return result;

        } catch (KeyringSignatureExecutor.Failure failure) {
            String detailCode = switch (failure.code()) {
                case KEY_UNAVAILABLE -> DC_KEY_NOT_FOUND;
                case ALGORITHM_MISMATCH -> DC_ALGORITHM_MISMATCH;
                case PROVIDER_FAILURE -> DC_CRYPTO_FAILURE;
            };
            if (failure.code() == KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE) {
                logSafeFailure("SIGN", detailCode, failure);
            }
            return new SignExecutionResult(failedStatus(detailCode));

        } catch (InvalidRequestException inv) {
            return new SignExecutionResult(failedStatus(inv.detailCode));

        } catch (KeyringSignatureExecutor.Cancellation cancelled) {
            OperationStatus status = new OperationStatus(State.CANCELLED, now(), Optional.of(DC_CANCELLED),
                    Optional.empty());
            return new SignExecutionResult(status);

        } catch (ContentIntegrityException integrityFailure) {
            logSafeFailure("SIGN", DC_CONTENT_INTEGRITY_FAILURE, integrityFailure);
            return new SignExecutionResult(failedStatus(DC_CONTENT_INTEGRITY_FAILURE));
        } catch (IOException io) {
            logSafeFailure("SIGN", DC_KEYRING_IO_ERROR, io);
            return new SignExecutionResult(failedStatus(DC_KEYRING_IO_ERROR));

        } catch (GeneralSecurityException sec) {
            logSafeFailure("SIGN", DC_CRYPTO_FAILURE, sec);
            return new SignExecutionResult(failedStatus(DC_CRYPTO_FAILURE));
        } finally {
            clearOwned("sign-result-raw", signatureBytes);
            if (encodedSignature != null) {
                encodedSignature.close();
            }
        }
    }

    private OperationStatus failedStatus(String detailCode) {
        return new OperationStatus(State.FAILED, now(), Optional.of(detailCode), Optional.empty());
    }

    private KeyringSignatureExecutor requireSignatureExecutor() throws IOException, GeneralSecurityException {
        return new KeyringSignatureExecutor(requireKeyringOrThrow(), session);
    }

    private boolean beginSign(SignRequest request, CallControl control) {
        PkiId operationId = request.submissionId();
        SignLockEntry entry = acquireOperationLock(operationId);
        OperationStatus event = null;
        try {
            String existingFingerprint = fingerprints.get(operationId);
            if (existingFingerprint != null) {
                if (!constantTimeEquals(existingFingerprint, request.semanticFingerprint())) {
                    throw new IllegalStateException("Signing submission ID conflicts with an existing request");
                }
                long existingFence = fences.getOrDefault(operationId, 0L);
                if (request.fencingToken() < existingFence) {
                    throw new IllegalStateException("Stale signing fencing token");
                }
                OperationStatus existing = statuses.get(operationId);
                if (request.fencingToken() > existingFence && existing != null && existing.state() == State.RUNNING) {
                    event = new OperationStatus(State.FAILED, now(), Optional.of("FENCE_SUPERSEDED"), Optional.empty());
                    fences.put(operationId, request.fencingToken());
                    statuses.put(operationId, event);
                }
                return false;
            }
            control.requireActive(now());
            fingerprints.put(operationId, request.semanticFingerprint());
            fences.put(operationId, request.fencingToken());
            requests.put(operationId, request);
            event = new OperationStatus(State.RUNNING, now(), Optional.of(DC_SUBMITTED), Optional.empty());
            statuses.put(operationId, event);
            return true;
        } finally {
            releaseOperationLock(operationId, entry);
            if (event != null) {
                notifySinks(operationId, event);
            }
        }
    }

    private void completeSign(SignRequest request, OperationStatus terminal) {
        PkiId operationId = request.submissionId();
        SignLockEntry entry = acquireOperationLock(operationId);
        boolean committed = false;
        OperationStatus notification = terminal;
        try {
            OperationStatus current = statuses.get(operationId);
            if (current != null && current.state() == State.RUNNING
                    && fences.getOrDefault(operationId, 0L) == request.fencingToken()
                    && constantTimeEquals(fingerprints.get(operationId), request.semanticFingerprint())) {
                OperationStatus committedStatus = terminal;
                if (terminal.state() == State.SUCCEEDED && deadlineReached(request.deadline(), terminal.updatedAt())) {
                    committedStatus = expiredStatus(terminal.updatedAt());
                }
                statuses.put(operationId, committedStatus);
                notification = committedStatus;
                committed = true;
            }
        } finally {
            releaseOperationLock(operationId, entry);
        }
        if (committed) {
            notifySinks(operationId, notification);
        }
    }

    private static boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        byte[] leftBytes = left.getBytes(StandardCharsets.US_ASCII);
        byte[] rightBytes = right.getBytes(StandardCharsets.US_ASCII);
        try {
            return MessageDigest.isEqual(leftBytes, rightBytes);
        } finally {
            Arrays.fill(leftBytes, (byte) 0);
            Arrays.fill(rightBytes, (byte) 0);
        }
    }

    /**
     * Submits a signature verification operation and returns its workflow operation
     * identifier.
     *
     * <p>
     * The operation is executed immediately in the caller thread. Verification can
     * be performed either against a public key resolved from
     * {@link VerifyRequest#publicKeyRef()} or against a caller-supplied encoded
     * public key from {@link VerifyRequest#publicKeyEncoded()}.
     * </p>
     *
     * <p>
     * The terminal successful result records only the boolean verification outcome.
     * A cryptographically valid signature produces detail code
     * {@link #DC_VERIFIED}, while a completed but rejected signature produces
     * detail code {@link #DC_REJECTED}. Structural or runtime failures are surfaced
     * as terminal {@link State#FAILED} statuses with stable detail codes.
     * </p>
     *
     * @param request verify request; must not be {@code null}
     * @return operation identifier that can be used to query the terminal result
     * @throws IllegalArgumentException if {@code request} is {@code null}
     */
    @Override
    public PkiId submitVerify(VerifyRequest request, CallControl control) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        Objects.requireNonNull(control, "control").requireActive(now());

        PkiId opId = newOperationId();
        putStatus(opId, new OperationStatus(State.RUNNING, now(), Optional.of(DC_SUBMITTED), Optional.empty()));

        byte[] signatureBytes = null;
        try {
            if (request.algorithmId() == null || request.algorithmId().isBlank()) {
                throw new InvalidRequestException(DC_INVALID_ALGORITHM_ID);
            }

            PublicKey pub = resolvePublicKeyOrThrow(request);

            signatureBytes = decodeSignatureOrThrow(request.signature());
            if (deadlineReached(request.deadline(), now())) {
                putStatus(opId, expiredStatus());
                return opId;
            }
            control.requireActive(now());
            request.cancellation().throwIfCancelled();
            boolean ok = verifyStreaming(request.algorithmId(), pub, request.content(), signatureBytes,
                    () -> request.cancellation().isCancelled() || control.cancellation().isCancelled()
                            || !now().isBefore(control.deadline()));

            Instant completedAt = now();
            control.requireActive(completedAt);
            if (deadlineReached(request.deadline(), completedAt)) {
                putStatus(opId, expiredStatus(completedAt));
                return opId;
            }
            OperationResult result = new OperationResult(Optional.empty(), Optional.of(ok));
            String dc = ok ? DC_VERIFIED : DC_REJECTED;
            putStatus(opId, new OperationStatus(State.SUCCEEDED, completedAt, Optional.of(dc), Optional.of(result)));
            return opId;

        } catch (InvalidRequestException inv) {
            putStatus(opId, new OperationStatus(State.FAILED, now(), Optional.of(inv.detailCode), Optional.empty()));
            return opId;

        } catch (IOException io) {
            putStatus(opId,
                    new OperationStatus(State.FAILED, now(), Optional.of(DC_KEYRING_IO_ERROR), Optional.empty()));
            logSafeFailure("VERIFY", DC_KEYRING_IO_ERROR, io);
            return opId;

        } catch (GeneralSecurityException sec) {
            putStatus(opId, new OperationStatus(State.FAILED, now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            logSafeFailure("VERIFY", DC_CRYPTO_FAILURE, sec);
            return opId;

        } catch (RuntimeException ex) { // NOPMD
            putStatus(opId, new OperationStatus(State.FAILED, now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            logSafeFailure("VERIFY", DC_CRYPTO_FAILURE, ex);
            return opId;
        } finally {
            clearOwned("verify-signature", signatureBytes);
        }
    }

    /**
     * Returns the current status of a previously submitted operation.
     *
     * <p>
     * Production signing statuses are read from the store-owned local ledger
     * participant; the transport-neutral standalone test path retains them only in
     * memory. Verification statuses are memory-only. Unknown operation identifiers
     * are mapped to a stable synthetic failed status with detail code
     * {@link #DC_UNKNOWN_OPERATION}; purged signing identifiers in the bound
     * namespace report {@link State#EXPIRED}.
     * </p>
     *
     * @param operationId workflow operation identifier; must not be {@code null}
     * @return current operation status, never {@code null}
     * @throws IllegalArgumentException if {@code operationId} is {@code null}
     */
    @Override
    public OperationStatus status(PkiId operationId, CallControl control) {
        if (operationId == null) {
            throw new IllegalArgumentException("operationId must not be null");
        }
        Objects.requireNonNull(control, "control").requireActive(now());
        OperationStatus memoryStatus = this.statuses.get(operationId);
        if (memoryStatus != null) {
            control.requireActive(now());
            return memoryStatus;
        }
        if (localLedger != null) {
            OperationStatus status = localLedger.localSignStatus(operationId);
            control.requireActive(now());
            return status;
        }
        purgeExpiredOperations();
        OperationStatus st = this.statuses.get(operationId);
        if (st == null) {
            try {
                SigningSubmissionId parsed = SigningSubmissionId.parse(operationId);
                String namespace = boundNamespace.get();
                if (namespace != null && namespace.equals(parsed.namespace())
                        && !now().isBefore(parsed.createdAt().plus(operationHorizon))) {
                    OperationStatus expired = new OperationStatus(State.EXPIRED, now(), Optional.of("EXPIRED"),
                            Optional.empty());
                    control.requireActive(now());
                    return expired;
                }
            } catch (IllegalArgumentException ignored) { // unknown verify operation identifiers remain synthetic failed
                // handled by the stable unknown status below
            }
            control.requireActive(now());
            return UNKNOWN_OPERATION_STATUS;
        }
        control.requireActive(now());
        return st;
    }

    /**
     * Attempts to cancel a non-terminal operation.
     *
     * <p>
     * Cancellation is serialized with completion for the same signing identifier
     * and validates the fencing token. Local execution first records cancellation
     * intent and reaches {@link State#CANCELLED} only after cryptographic execution
     * acknowledges the shared cancellation signal. It
     * A replay of an accepted cancellation with the same operation identifier and
     * fence succeeds without another state change, regardless of its safe reason.
     * </p>
     *
     * @param operationId workflow operation identifier; must not be {@code null}
     * @param reason      caller-supplied cancellation reason; must not be
     *                    {@code null} or blank
     * @return {@code true} if the operation was transitioned to
     *         {@link State#CANCELLED}, otherwise {@code false}
     * @throws IllegalArgumentException if {@code operationId} is {@code null} or if
     *                                  {@code reason} is {@code null} or blank
     */
    @Override
    public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
        if (operationId == null) {
            throw new IllegalArgumentException("operationId must not be null");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        if (fencingToken < MIN_FENCING_TOKEN) {
            throw new IllegalArgumentException("fencingToken must be positive");
        }
        Objects.requireNonNull(control, "control").requireActive(now());
        if (localLedger != null && !statuses.containsKey(operationId)) {
            boolean accepted = localLedger.cancelLocalSign(operationId, fencingToken);
            if (accepted) {
                notifySinks(operationId, localLedger.localSignStatus(operationId));
            }
            return accepted;
        }
        SignLockEntry entry = acquireOperationLock(operationId);
        OperationStatus cancelled = null;
        try {
            OperationStatus st = this.statuses.get(operationId);
            if (st == null) {
                control.requireActive(now());
                return false;
            }
            long currentFence = this.fences.getOrDefault(operationId, 0L);
            if (st.isTerminal()) {
                control.requireActive(now());
                return st.state() == State.CANCELLED && fencingToken == currentFence;
            }
            if (fencingToken < currentFence) {
                control.requireActive(now());
                return false;
            }
            control.requireActive(now());
            this.fences.put(operationId, fencingToken);
            this.cancellationReasons.putIfAbsent(operationId, cancellationReasonFingerprint(reason));
            cancelled = new OperationStatus(State.CANCELLED, now(), Optional.of(DC_CANCELLED), Optional.empty());
            statuses.put(operationId, cancelled);
        } finally {
            releaseOperationLock(operationId, entry);
            if (cancelled != null) {
                notifySinks(operationId, cancelled);
            }
        }
        control.requireActive(now());
        return true;
    }

    /**
     * Registers a notification sink that will be called on subsequent status
     * changes observed by this provider instance.
     *
     * <p>
     * The returned registration must be closed by the caller when notifications are
     * no longer needed. Sink failures are isolated and must not break the provider.
     * </p>
     *
     * @param sink notification sink; must not be {@code null}
     * @return registration handle used to unregister the sink
     * @throws IllegalArgumentException if {@code sink} is {@code null}
     */
    @Override
    public Registration register(NotificationSink sink) {
        if (sink == null) {
            throw new IllegalArgumentException("sink must not be null");
        }
        PkiId regId = newOperationId();
        this.sinks.put(regId, sink);
        return new Registration() {
            @Override
            public void close() {
                sinks.remove(regId);
            }
        };
    }

    /**
     * Clears memory-resident state and closes the workflow-owned keyring.
     */
    @Override
    @SuppressWarnings("PMD.CloseResource")
    public void close() {
        KeyringStore keyring;
        keyringLifecycleLock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            keyring = this.keyringOrNull;
            this.keyringOrNull = null;
        } finally {
            keyringLifecycleLock.unlock();
        }
        this.statuses.clear();
        this.fingerprints.clear();
        this.fences.clear();
        this.cancellationReasons.clear();
        this.requests.clear();
        this.sinks.clear();
        if (keyring != null) {
            keyring.close();
        }
    }

    @SuppressWarnings("PMD.CloseResource")
    private KeyringStore requireKeyringOrThrow() throws IOException, GeneralSecurityException {
        keyringLifecycleLock.lock();
        try {
            if (closed) {
                throw new IOException("Signature workflow is closed");
            }
            KeyringStore ks = this.keyringOrNull;
            if (ks != null) {
                return ks;
            }
            try (KeyringPassword password = acquireKeyringPassword()) {
                KeyringStore loaded = KeyringStore.open(this.keyringPath, password);
                if (closed) {
                    loaded.close();
                    throw new IOException("Signature workflow is closed");
                }
                this.keyringOrNull = loaded;
                return loaded;
            }
        } finally {
            keyringLifecycleLock.unlock();
        }
    }

    private KeyringPassword acquireKeyringPassword() throws IOException {
        KeyringPassword password = this.keyringUnlockProvider.acquire();
        if (password == null) {
            throw new IOException("Keyring unlock provider returned no password");
        }
        return password;
    }

    private static void enforceAlgorithmMatchOrThrow(String requested, String stored) throws InvalidRequestException {
        String reqKeyAlg = keyAlgorithmId(requested);
        String storedKeyAlg = keyAlgorithmId(stored);
        if (!reqKeyAlg.equals(storedKeyAlg)) {
            throw new InvalidRequestException(DC_ALGORITHM_MISMATCH);
        }
    }

    private KeyRefParts parseKeyRefOrThrow(KeyRef keyRef, boolean forSigning) throws InvalidRequestException {
        String raw = keyRef.value();
        if (!raw.startsWith(this.keyRefPrefix)) {
            throw new InvalidRequestException(DC_INVALID_KEYREF_PREFIX);
        }

        String v = raw.substring(this.keyRefPrefix.length());
        boolean hasPrv = v.endsWith(".prv");
        boolean hasPub = v.endsWith(".pub");

        if (this.requireComponentSuffix) {
            if (forSigning && !hasPrv) {
                throw new InvalidRequestException(DC_INVALID_KEYREF_SUFFIX);
            }
            if (!forSigning && !hasPub) {
                throw new InvalidRequestException(DC_INVALID_KEYREF_SUFFIX);
            }
        }

        if (forSigning) {
            String privateAlias = hasPrv ? v : (v + ".prv");
            return new KeyRefParts(privateAlias, null);
        }

        String publicAlias = hasPub ? v : (v + ".pub");
        return new KeyRefParts(publicAlias, publicAlias);
    }

    @SuppressWarnings("PMD.CloseResource")
    private PublicKey resolvePublicKeyOrThrow(VerifyRequest request)
            throws InvalidRequestException, IOException, GeneralSecurityException {

        if (request.publicKeyRef().isPresent()) {
            KeyRefParts parts = parseKeyRefOrThrow(request.publicKeyRef().get(), false);

            KeyringStore ks = requireKeyringOrThrow();

            KeyringStore.PublicWithId pub;
            try {
                pub = ks.getPublicWithId(parts.publicAlias);
            } catch (GeneralSecurityException missing) {
                throw new InvalidRequestException(DC_KEY_NOT_FOUND, missing);
            }

            enforceAlgorithmMatchOrThrow(request.algorithmId(), pub.algorithm());
            return pub.key();
        }

        if (request.publicKeyEncoded().isPresent()) {
            byte[] spki = decodePublicKeyOrThrow(request.publicKeyEncoded().get());
            try {
                AlgorithmKeySpec spec = createPublicKeySpecOrThrow(request.algorithmId(), spki);
                String keyAlg = keyAlgorithmId(request.algorithmId());
                return importPublic(keyAlg, spec);
            } catch (GeneralSecurityException ex) {
                throw new InvalidRequestException(DC_CRYPTO_FAILURE, ex);
            } finally {
                clearOwned("verify-public-key", spki);
            }
        }

        throw new InvalidRequestException(DC_UNSUPPORTED_PUBLICKEY_FORM);
    }

    @Override
    public EncodedObject resolvePublicKeyInfo(KeyRef keyRef) {
        Objects.requireNonNull(keyRef, "keyRef");
        try {
            KeyRefParts parts = parseKeyRefOrThrow(keyRef, true);
            String privateAlias = parts.privateAlias;
            String logicalAlias = privateAlias.endsWith(".prv")
                    ? privateAlias.substring(0, privateAlias.length() - ".prv".length()) : privateAlias;
            PublicKey publicKey = requireKeyringOrThrow().getPublic(logicalAlias);
            return new EncodedObject(Encoding.DER, publicKey.getEncoded());
        } catch (InvalidRequestException | IOException | GeneralSecurityException failure) {
            throw new PkiException("Managed public key resolution failed: code=PUBLIC_KEY_RESOLUTION_FAILED", failure);
        }
    }

    private <S extends AlgorithmKeySpec> PublicKey importPublic(String algorithmId, S spec)
            throws GeneralSecurityException {
        @SuppressWarnings("unchecked")
        Class<S> specType = (Class<S>) spec.getClass();
        return session.keyBuilders().asymmetric().publicImporter(algorithmId, specType).importPublic(spec);
    }

    private byte[] decodePublicKeyOrThrow(EncodedObject publicKey) throws InvalidRequestException {
        byte[] encoded = publicKey.bytes();
        if (publicKey.encoding() == Encoding.DER || publicKey.encoding() == Encoding.BINARY) {
            return encoded;
        }
        if (publicKey.encoding() == Encoding.PEM) {
            try {
                return pemUnwrap(new String(encoded, StandardCharsets.US_ASCII));
            } finally {
                clearOwned("verify-public-key-encoding", encoded);
            }
        }
        clearOwned("verify-public-key-encoding", encoded);
        throw new InvalidRequestException(DC_UNSUPPORTED_PUBLICKEY_FORM);
    }

    private static AlgorithmKeySpec createPublicKeySpecOrThrow(String algorithmId, byte[] spkiDer)
            throws InvalidRequestException {
        String keyAlg = keyAlgorithmId(algorithmId);
        if (keyAlg == null || keyAlg.isBlank()) {
            throw new InvalidRequestException(DC_UNSUPPORTED_PUBLICKEY_FORM);
        }

        return switch (keyAlg) {
            case "RSA" -> new RsaPublicKeySpec(spkiDer);
            case "ECDSA" -> new EcdsaPublicKeySpec(spkiDer);
            case "Ed25519" -> new Ed25519PublicKeySpec(spkiDer);
            case "Ed448" -> new Ed448PublicKeySpec(spkiDer);
            case "ML-DSA" -> new MldsaPublicKeySpec(spkiDer);
            case "SPHINCS+" -> new SphincsPlusPublicKeySpec(spkiDer);
            case "SLH-DSA" -> new SlhDsaPublicKeySpec(spkiDer);
            default -> throw new InvalidRequestException(DC_UNSUPPORTED_PUBLICKEY_FORM);
        };
    }

    /**
     * Resolves the key algorithm identifier used for key import and key matching.
     *
     * <p>
     * Standard interoperable signature names such as {@code SHA256withRSA} are
     * first mapped through {@link SignatureInteropProfiles}. For all other
     * algorithms, the historical normalization remains in place so that
     * ZeroEcho-native PQC or application-specific identifiers continue to work
     * unchanged.
     * </p>
     *
     * @param algorithmId algorithm id provided by the caller
     * @return key algorithm id
     */
    private static String keyAlgorithmId(String algorithmId) {
        if (algorithmId == null) {
            return "";
        }
        Optional<SignatureInteropProfile> profile = SignatureInteropProfiles.resolve(algorithmId.trim());
        if (profile.isPresent()) {
            return profile.get().keyAlgorithmId();
        }
        String a = algorithmId.trim();
        if (a.endsWith("withRSA")) {
            return "RSA";
        }
        if (a.endsWith("withECDSA")) {
            return "ECDSA";
        }
        return a;
    }

    private boolean verifyStreaming(String algorithmId, PublicKey pub, RepeatableContent content, byte[] signature,
            CancellationSignal cancellation)
            throws GeneralSecurityException, IOException {

        Optional<SignatureInteropProfile> profile = SignatureInteropProfiles.resolve(algorithmId);
        String contextAlgorithmId = profile.map(SignatureInteropProfile::contextAlgorithmId).orElse(algorithmId);
        ContextSpec contextSpec = profile.map(SignatureInteropProfile::contextSpec).orElse(null);
        byte[] internalSignature = signature;
        boolean convertedSignature = false;
        if (profile.isPresent()) {
            internalSignature = profile.get().externalToInternalSignature(signature);
            convertedSignature = true;
        }

        try (SignatureContext verifier = session.createContext(contextAlgorithmId, KeyUsage.VERIFY, pub, contextSpec)) {
            verifier.setExpectedTag(internalSignature);
            try (InputStream source = content.openStream(); InputStream in = verifier.wrap(source)) {
                consume(in, cancellation);
            }
            return true;
        } catch (Exception mismatch) {
            return false;
        } finally {
            if (convertedSignature) {
                clearOwned("verify-internal-signature", internalSignature);
            }
        }
    }

    private static void consume(InputStream input, CancellationSignal cancellation) throws IOException {
        byte[] buffer = new byte[16 * 1024];
        try {
            while (input.read(buffer) >= 0) {
                cancellation.throwIfCancelled();
            }
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    private OwnedEncodedSignature encodeSignatureForTransfer(Encoding encoding, byte[] sigBytes)
            throws InvalidRequestException {
        if (encoding == Encoding.BINARY || encoding == Encoding.DER) {
            return new OwnedEncodedSignature(encoding, sigBytes);
        }
        if (encoding == Encoding.PEM) {
            String pem = pemWrap("ZEROECHO SIGNATURE", sigBytes);
            byte[] encoded = pem.getBytes(StandardCharsets.US_ASCII);
            return new OwnedEncodedSignature(Encoding.PEM, encoded);
        }
        throw new InvalidRequestException(DC_UNSUPPORTED_SIGNATURE_ENCODING);
    }

    private byte[] decodeSignatureOrThrow(EncodedObject signature) throws InvalidRequestException {
        byte[] encoded = signature.bytes();
        if (signature.encoding() == Encoding.BINARY || signature.encoding() == Encoding.DER) {
            return encoded;
        }
        if (signature.encoding() == Encoding.PEM) {
            try {
                return pemUnwrap(new String(encoded, StandardCharsets.US_ASCII));
            } finally {
                clearOwned("verify-signature-encoding", encoded);
            }
        }
        clearOwned("verify-signature-encoding", encoded);
        throw new InvalidRequestException(DC_UNSUPPORTED_SIGNATURE_ENCODING);
    }

    private static String pemWrap(String label, byte[] data) {
        String b64 = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(data);
        return "-----BEGIN " + label + "-----\n" + b64 + "\n-----END " + label + "-----\n";
    }

    private static byte[] pemUnwrap(String pem) {
        String[] lines = pem.replace("\r", "").split("\n");
        StringBuilder b64 = new StringBuilder();
        for (String line : lines) {
            if (line.startsWith("-----BEGIN ") || line.startsWith("-----END ")) {
                continue;
            }
            String t = line.trim();
            if (!t.isEmpty()) {
                b64.append(t);
            }
        }
        return Base64.getDecoder().decode(b64.toString());
    }

    private void putStatus(PkiId id, OperationStatus st) {
        this.statuses.put(id, st);
        notifySinks(id, st);
    }

    private void notifySinks(PkiId id, OperationStatus st) {
        for (NotificationSink sink : this.sinks.values()) {
            try {
                sink.onStatusChanged(id, st);
            } catch (Throwable ignore) {
                // sink must not break provider
                logSafeFailure("CALLBACK", "NOTIFICATION_FAILED", ignore);
            }
        }
    }

    private static void logSafeFailure(String operation, String code, Throwable failure) {
        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "{0} failed: code={1}, exception={2}",
                    new Object[] { operation, code, failure.getClass().getName() });
        }
    }

    private void clearOwned(String category, byte[] owned) {
        if (owned != null) {
            Arrays.fill(owned, (byte) 0);
            cleanupObserver.accept(category, owned);
        }
    }

    private SignLockEntry acquireOperationLock(PkiId operationId) {
        SignLockEntry entry = operationLocks.compute(operationId, (ignored, current) -> {
            SignLockEntry selected = current == null ? new SignLockEntry() : current;
            selected.references.incrementAndGet();
            return selected;
        });
        entry.lock.lock();
        return entry;
    }

    private void releaseOperationLock(PkiId operationId, SignLockEntry entry) {
        entry.lock.unlock();
        operationLocks.computeIfPresent(operationId, (ignored, current) -> {
            if (!current.equals(entry)) {
                return current;
            }
            return current.references.decrementAndGet() == 0 ? null : current;
        });
    }

    /**
     * Reference-counted lock entry removed after the last operation user exits.
     */
    private static final class SignLockEntry {
        private final ReentrantLock lock = new ReentrantLock();
        private final AtomicInteger references = new AtomicInteger();
    }

    private Instant now() {
        if (localLedger != null) {
            return localLedger.signingNow();
        }
        timeWatermarkLock.lock();
        try {
            long monotonic = Math.max(timeWatermark.get(), clock.instant().toEpochMilli());
            timeWatermark.set(monotonic);
            return Instant.ofEpochMilli(monotonic);
        } finally {
            timeWatermarkLock.unlock();
        }
    }

    private static boolean deadlineReached(Optional<Instant> deadline, Instant observedAt) {
        return deadline.isPresent() && !observedAt.isBefore(deadline.get());
    }

    private OperationStatus expiredStatus() {
        return expiredStatus(now());
    }

    private static OperationStatus expiredStatus(Instant completedAt) {
        return new OperationStatus(State.EXPIRED, completedAt, Optional.of("EXPIRED"), Optional.empty());
    }

    private void purgeExpiredOperations() {
        if (localLedger != null) {
            return;
        }
        Instant current = now();
        for (Map.Entry<PkiId, SignRequest> mapEntry : requests.entrySet()) {
            PkiId operationId = mapEntry.getKey();
            if (!current.isBefore(SigningSubmissionId.parse(operationId).createdAt().plus(operationHorizon))) {
                SignLockEntry lock = acquireOperationLock(operationId);
                try {
                    if (requests.containsKey(operationId) && !current
                            .isBefore(SigningSubmissionId.parse(operationId).createdAt().plus(operationHorizon))) {
                        requests.remove(operationId);
                        fingerprints.remove(operationId);
                        fences.remove(operationId);
                        cancellationReasons.remove(operationId);
                        statuses.remove(operationId);
                    }
                } finally {
                    releaseOperationLock(operationId, lock);
                }
            }
        }
    }

    private static String cancellationReasonFingerprint(String reason) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(reason.getBytes(StandardCharsets.UTF_8));
            try {
                return HexFormat.of().formatHex(digest);
            } finally {
                Arrays.fill(digest, (byte) 0);
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }

    private static PkiId newOperationId() {
        return new PkiId(UUID.randomUUID().toString());
    }

    /** Package-local dependencies used to exercise provider failure boundaries. */
    /* default */ record SigningDependencies(KeyringStore keyring, ZeroEchoSession session) {
        SigningDependencies {
            Objects.requireNonNull(keyring, "keyring must not be null");
            Objects.requireNonNull(session, "session must not be null");
        }
    }

    /**
     * Parsed, provider-local representation of a {@link KeyRef}.
     *
     * <p>
     * This is an internal helper that translates an opaque {@link KeyRef} into
     * concrete keyring aliases. The mapping is intentionally provider-specific: PKI
     * must treat {@link KeyRef} as an opaque identifier and must never rely on
     * parsing rules.
     * </p>
     *
     * <h2>Security</h2>
     * <ul>
     * <li>This type must never contain private key material; it only carries alias
     * strings.</li>
     * <li>Instances must not be logged in production, as aliases can be sensitive
     * operational metadata.</li>
     * </ul>
     *
     * <p>
     * For signing requests, {@link #privateAlias} addresses the authoritative
     * private component (e.g. {@code *.prv}) and {@link #publicAlias} is unused.
     * For verification, {@link #privateAlias} is unused and {@link #publicAlias}
     * addresses the public component.
     * </p>
     */
    private static final class KeyRefParts {
        private final String privateAlias;
        private final String publicAlias;

        private KeyRefParts(String privateAlias, String publicAlias) {
            this.privateAlias = privateAlias;
            this.publicAlias = publicAlias;
        }
    }

    /**
     * Terminal status and the executor-owned signature copy that must be cleared
     * after the status is committed.
     */
    private final class SignExecutionResult implements AutoCloseable {
        private final State state;
        private final Instant updatedAt;
        private final Optional<String> detailCode;
        private final Encoding signatureEncoding;
        private byte[] signatureBytes;

        private SignExecutionResult(OperationStatus terminal) {
            state = terminal.state();
            updatedAt = terminal.updatedAt();
            detailCode = terminal.detailCode();
            signatureEncoding = null;
        }

        private SignExecutionResult(Instant completedAt, OwnedEncodedSignature signature) {
            state = State.SUCCEEDED;
            updatedAt = completedAt;
            detailCode = Optional.of(DC_SIGNED);
            signatureEncoding = signature.encoding;
            signatureBytes = signature.transfer();
        }

        private OperationStatus status() {
            Optional<OperationResult> result = signatureBytes == null
                    ? Optional.empty()
                    : Optional.of(new OperationResult(
                            Optional.of(new EncodedObject(signatureEncoding, signatureBytes)), Optional.empty()));
            return new OperationStatus(state, updatedAt, detailCode, result);
        }

        private byte[] transferSignature() {
            byte[] transferred = signatureBytes;
            signatureBytes = null;
            return transferred;
        }

        @Override
        public void close() {
            clearOwned("sign-final-result", signatureBytes);
            signatureBytes = null;
        }
    }

    /** Sole owner of the final encoded output before terminal-result transfer. */
    private final class OwnedEncodedSignature implements AutoCloseable {
        private final Encoding encoding;
        private byte[] bytes;

        private OwnedEncodedSignature(Encoding encoding, byte[] bytes) {
            this.encoding = Objects.requireNonNull(encoding, "encoding");
            this.bytes = Objects.requireNonNull(bytes, "bytes");
        }

        private byte[] transfer() {
            byte[] transferred = bytes;
            bytes = null;
            return transferred;
        }

        @Override public void close() {
            clearOwned("sign-encoded-result", bytes);
            bytes = null;
        }
    }

    /** Explicit owner of one locally computed terminal result pending persistence. */
    public final class LocalTerminalCompletion implements AutoCloseable {
        private final PkiId operationId;
        private final SignRequest request;
        private final State state;
        private final Instant updatedAt;
        private final Optional<String> detailCode;
        private final Encoding signatureEncoding;
        private final byte[] signatureBytes;
        private final RuntimeException postCommitFailure;
        private final ReentrantLock lifecycle = new ReentrantLock();
        private boolean closed;

        private LocalTerminalCompletion(PkiId operationId, SignRequest request,
                OperationStatus status, RuntimeException postCommitFailure,
                byte[] signatureBytes) {
            this.operationId = Objects.requireNonNull(operationId, "operationId");
            this.request = request;
            this.state = status == null ? null : status.state();
            this.updatedAt = status == null ? null : status.updatedAt();
            this.detailCode = status == null ? Optional.empty() : status.detailCode();
            this.signatureEncoding = status == null ? null : status.result()
                    .flatMap(OperationResult::signature).map(EncodedObject::encoding).orElse(null);
            this.signatureBytes = signatureBytes;
            this.postCommitFailure = postCommitFailure;
        }

        private LocalTerminalCompletion(PkiId operationId, SignRequest request,
                SignExecutionResult execution, RuntimeException postCommitFailure) {
            this.operationId = Objects.requireNonNull(operationId, "operationId");
            this.request = request;
            this.state = execution.state;
            this.updatedAt = execution.updatedAt;
            this.detailCode = execution.detailCode;
            this.signatureEncoding = execution.signatureEncoding;
            this.signatureBytes = execution.transferSignature();
            this.postCommitFailure = postCommitFailure;
        }

        /**
         * Returns the durably accepted operation identifier without committing.
         *
         * @return accepted durable operation identifier
         */
        public PkiId acceptedResult() {
            return operationId;
        }

        /**
         * Persists the terminal result without repeating cryptography.
         *
         * @return committed durable operation identifier
         */
        public PkiId commit() {
            lifecycle.lock();
            try {
                if (closed) {
                    throw new IllegalStateException("Local terminal completion is closed");
                }
                if (request != null) {
                    OperationStatus terminal = terminalStatus();
                    if (!localLedger.completeLocalSign(request, terminal)) {
                        throw new IllegalStateException(
                                "Local signing completion was not committed: code=LOCAL_SIGN_COMPLETION_UNCONFIRMED");
                    }
                    notifySinks(operationId, terminal);
                }
                if (postCommitFailure != null) {
                    throw postCommitFailure;
                }
                return operationId;
            } finally {
                lifecycle.unlock();
            }
        }

        private OperationStatus terminalStatus() {
            Optional<OperationResult> result = signatureBytes == null
                    ? Optional.empty()
                    : Optional.of(new OperationResult(
                            Optional.of(new EncodedObject(signatureEncoding, signatureBytes)), Optional.empty()));
            return new OperationStatus(state, updatedAt, detailCode, result);
        }

        /** Clears the owned result bytes after their terminal disposition. */
        @Override
        public void close() {
            lifecycle.lock();
            try {
                if (!closed) {
                    closed = true;
                    clearOwned("suspended-terminal-result", signatureBytes);
                }
            } finally {
                lifecycle.unlock();
            }
        }
    }

    /** One-shot streaming verifier shared by commitment validation and cryptography. */
    private static final class CommittedContent implements RepeatableContent {
        private final RepeatableContent delegate;
        private final ContentCommitment commitment;
        private final AtomicBoolean opened = new AtomicBoolean();

        private CommittedContent(RepeatableContent delegate, ContentCommitment commitment) {
            this.delegate = Objects.requireNonNull(delegate, "delegate");
            this.commitment = Objects.requireNonNull(commitment, "commitment");
        }

        @Override
        @SuppressWarnings("PMD.PreserveStackTrace") // Stable marker deliberately redacts delegate diagnostics.
        public InputStream openStream() throws IOException {
            if (!opened.compareAndSet(false, true)) {
                throw new ContentIntegrityException();
            }
            try {
                return new CommitmentInputStream(delegate.openStream(), commitment);
            } catch (RuntimeException failure) {
                throw new ContentIntegrityException();
            }
        }

        @Override
        public java.util.OptionalLong length() {
            return java.util.OptionalLong.of(commitment.length());
        }

        @Override
        public String contentId() {
            return "commitment:" + commitment.version();
        }

        @Override
        public void close() {
            // The caller retains ownership of the durable content handle.
        }
    }

    /** Digesting stream that validates exact length and SHA-256 at its only EOF. */
    @SuppressWarnings({ "PMD.AvoidMessageDigestField", "PMD.PreserveStackTrace" })
    private static final class CommitmentInputStream extends FilterInputStream {
        private final ContentCommitment commitment;
        private final MessageDigest digest;
        private long count;
        private boolean validated;

        private CommitmentInputStream(InputStream input, ContentCommitment commitment) {
            super(Objects.requireNonNull(input, "input"));
            this.commitment = Objects.requireNonNull(commitment, "commitment");
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException unavailable) {
                throw new IllegalStateException("SHA-256 is unavailable");
            }
        }

        @Override
        public int read() throws IOException {
            int value;
            try {
                value = super.read();
            } catch (java.io.InterruptedIOException sourceInterrupted) {
                throw sourceInterrupted;
            } catch (IOException sourceFailure) {
                throw new ContentIntegrityException();
            }
            if (value < 0) {
                validateAtEnd();
            } else {
                digest.update((byte) value);
                count = Math.addExact(count, 1L);
                rejectExcessLength();
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            int read;
            try {
                read = super.read(bytes, offset, length);
            } catch (java.io.InterruptedIOException sourceInterrupted) {
                throw sourceInterrupted;
            } catch (IOException sourceFailure) {
                throw new ContentIntegrityException();
            }
            if (read < 0) {
                validateAtEnd();
            } else if (read > 0) {
                digest.update(bytes, offset, read);
                count = Math.addExact(count, read);
                rejectExcessLength();
            }
            return read;
        }

        private void rejectExcessLength() throws ContentIntegrityException {
            if (count > commitment.length()) {
                throw new ContentIntegrityException();
            }
        }

        private void validateAtEnd() throws ContentIntegrityException {
            if (validated) {
                return;
            }
            validated = true;
            byte[] actual = digest.digest();
            byte[] expected = HexFormat.of().parseHex(commitment.sha256());
            try {
                if (count != commitment.length() || !MessageDigest.isEqual(actual, expected)) {
                    throw new ContentIntegrityException();
                }
            } finally {
                Arrays.fill(actual, (byte) 0);
                Arrays.fill(expected, (byte) 0);
            }
        }
    }

    /** Cause-free stable marker for content commitment mismatch. */
    private static final class ContentIntegrityException extends IOException {
        private static final long serialVersionUID = 1L;

        private ContentIntegrityException() {
            super(DC_CONTENT_INTEGRITY_FAILURE);
        }
    }

    /**
     * Internal exception used to signal validation/policy failures that must be
     * surfaced via operation status.
     *
     * <p>
     * This exception must never escape the public boundary of
     * {@link ZeroEchoLibSignatureWorkflow}. It is caught by
     * {@code submitSign}/{@code submitVerify} and converted to a deterministic
     * status: {@link State#FAILED} with a stable {@code detailCode}.
     * </p>
     *
     * <h2>Design constraints</h2>
     * <ul>
     * <li>{@code detailCode} must be non-sensitive and stable, suitable for audit
     * logs and transport-level APIs.</li>
     * <li>The exception message is set to {@code detailCode} for diagnostics only;
     * callers must not depend on it.</li>
     * <li>{@code cause} may be attached for local diagnostics but must not be used
     * to derive user-facing output.</li>
     * </ul>
     */
    private static final class InvalidRequestException extends Exception {
        private static final long serialVersionUID = 2058759559902131220L;
        private final String detailCode;

        private InvalidRequestException(String detailCode) {
            super(detailCode);
            this.detailCode = detailCode;
        }

        private InvalidRequestException(String detailCode, Throwable cause) {
            super(detailCode, cause);
            this.detailCode = detailCode;
        }
    }
}
