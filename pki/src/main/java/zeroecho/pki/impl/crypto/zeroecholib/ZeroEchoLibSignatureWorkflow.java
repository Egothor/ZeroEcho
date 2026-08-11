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

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
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
 * immediately in the caller thread. Signing requests and terminal outcomes are
 * retained durably in the configured operation root for the configured
 * operation horizon.
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
 * closed. On restart, retained terminal operations remain queryable, while a
 * retained {@link State#RUNNING} operation is durably converted to
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
 * signature result are stored durably until the configured operation horizon.
 * Exact submissions attach to these records after restart.</li>
 * <li>A signing record found in {@link State#RUNNING} during restart is changed
 * durably to {@link State#FAILED} with detail {@code RECOVERY_INCOMPLETE};
 * signing is not replayed.</li>
 * <li>Verification statuses and notification registrations are memory-only and
 * are lost when the provider is closed or the process restarts.</li>
 * <li>The underlying {@link KeyringStore} is loaded lazily on first use and
 * then cached in the provider instance.</li>
 * <li>{@link #close()} clears memory-resident caches and registrations and
 * releases the operation-root lock. It does not delete retained signing
 * records.</li>
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
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity", "PMD.TooManyMethods",
        "PMD.NcssCount", "PMD.CloseResource", "PMD.ExceptionAsFlowControl",
        "PMD.AvoidCatchingGenericException" })
public final class ZeroEchoLibSignatureWorkflow implements SignatureWorkflow, PublicKeyInfoSource {

    private static final Logger LOG = Logger.getLogger(ZeroEchoLibSignatureWorkflow.class.getName());

    // Stable detail codes (non-secret), intended for audit + transport mapping.
    public static final String DC_SUBMITTED = "SUBMITTED";
    public static final String DC_SIGNED = "SIGNED";
    public static final String DC_VERIFIED = "VERIFIED";
    public static final String DC_REJECTED = "REJECTED";
    public static final String DC_CANCELLED = "CANCELLED";

    public static final String DC_INVALID_KEYREF_SUFFIX = "INVALID_KEYREF_SUFFIX";
    public static final String DC_INVALID_KEYREF_PREFIX = "INVALID_KEYREF_PREFIX";
    public static final String DC_UNSUPPORTED_PUBLICKEY_FORM = "UNSUPPORTED_PUBLICKEY_FORM";
    public static final String DC_INVALID_ALGORITHM_ID = "INVALID_ALGORITHM_ID";
    public static final String DC_ALGORITHM_MISMATCH = "ALGORITHM_MISMATCH";
    public static final String DC_KEYRING_IO_ERROR = "KEYRING_IO_ERROR";
    public static final String DC_KEY_NOT_FOUND = "KEY_NOT_FOUND";
    public static final String DC_CRYPTO_FAILURE = "CRYPTO_FAILURE";
    public static final String DC_UNSUPPORTED_SIGNATURE_ENCODING = "UNSUPPORTED_SIGNATURE_ENCODING";
    public static final String DC_UNKNOWN_OPERATION = "UNKNOWN_OPERATION";

    private static final OperationStatus UNKNOWN_OPERATION_STATUS = new OperationStatus(State.FAILED, Instant.EPOCH,
            Optional.of(DC_UNKNOWN_OPERATION), Optional.empty());
    private static final int OPERATION_RECORD_VERSION = 5;
    private static final int PREVIOUS_OPERATION_RECORD_VERSION = 4;
    private static final long MIN_FENCING_TOKEN = 1L;

    private final String id;
    private final Path keyringPath;
    private final Path operationRoot;
    private final Clock clock;
    private final Duration operationHorizon;
    private final String keyRefPrefix;
    private final boolean requireComponentSuffix;
    private final ZeroEchoSession session;
    private final KeyringUnlockProvider keyringUnlockProvider;

    private final ConcurrentMap<PkiId, OperationStatus> statuses;
    private final ConcurrentMap<PkiId, String> fingerprints;
    private final ConcurrentMap<PkiId, Long> fences;
    private final ConcurrentMap<PkiId, String> cancellationReasons;
    private final ConcurrentMap<PkiId, SignRequest> requests;
    private final ConcurrentMap<PkiId, NotificationSink> sinks;
    private final ConcurrentMap<PkiId, SignLockEntry> operationLocks;
    private final FileChannel ownershipChannel;
    private final FileLock ownershipLock;
    private final AtomicLong timeWatermark;
    private final ReentrantLock timeWatermarkLock;
    private final AtomicReference<String> boundNamespace;
    private final ReentrantLock domainLock;
    private final ReentrantLock keyringLifecycleLock;
    private final BiConsumer<String, byte[]> cleanupObserver;

    private volatile KeyringStore keyringOrNull; // NOPMD
    private boolean closed;

    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path operationRoot, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider) {
        this(id, keyringPath, operationRoot, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, (category, cleared) -> {
                });
    }

    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path operationRoot, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, KeyringStore keyring) {
        this(id, keyringPath, operationRoot, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider);
        this.keyringOrNull = Objects.requireNonNull(keyring, "keyring must not be null");
    }

    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path operationRoot, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, SigningDependencies signingDependencies) {
        this(id, keyringPath, operationRoot, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, (category, cleared) -> {
                }, signingDependencies.session());
        this.keyringOrNull = signingDependencies.keyring();
    }

    /* default */ ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path operationRoot, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, BiConsumer<String, byte[]> cleanupObserver) {
        this(id, keyringPath, operationRoot, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                keyringUnlockProvider, cleanupObserver, new ZeroEchoSession());
    }

    private ZeroEchoLibSignatureWorkflow(String id, Path keyringPath, Path operationRoot, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider keyringUnlockProvider, BiConsumer<String, byte[]> cleanupObserver,
            ZeroEchoSession session) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (keyringPath == null) {
            throw new IllegalArgumentException("keyringPath must not be null");
        }
        if (operationRoot == null) {
            throw new IllegalArgumentException("operationRoot must not be null");
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
        this.operationRoot = operationRoot.toAbsolutePath().normalize();
        this.clock = clock;
        this.operationHorizon = operationHorizon;
        this.keyRefPrefix = keyRefPrefix;
        this.requireComponentSuffix = requireComponentSuffix;
        this.cleanupObserver = cleanupObserver;
        this.keyringUnlockProvider = keyringUnlockProvider;
        this.session = Objects.requireNonNull(session, "session must not be null");

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
        FileChannel acquiredChannel = null;
        FileLock acquiredLock = null;
        try {
            Files.createDirectories(this.operationRoot);
            restrictPermissions(this.operationRoot, true);
            Path owner = this.operationRoot.resolve("OWNER");
            if (Files.exists(owner)) {
                String storedOwner = Files.readString(owner);
                if (!id.equals(storedOwner)) {
                    throw new IllegalStateException("Signing operation root belongs to a different provider");
                }
            } else {
                Files.writeString(owner, id, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            }
            acquiredChannel = FileChannel.open(this.operationRoot.resolve(".lock"), StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE);
            acquiredLock = acquiredChannel.tryLock();
            if (acquiredLock == null) {
                throw new IllegalStateException("Signing operation root is already in use");
            }
            this.timeWatermark = new AtomicLong(loadTimeWatermark());
            Path domain = this.operationRoot.resolve("DOMAIN");
            this.boundNamespace = new AtomicReference<>(
                    Files.exists(domain) ? Files.readString(domain, StandardCharsets.US_ASCII).trim() : null);
            loadOperationRecords();
            purgeExpiredOperations();
            this.ownershipChannel = acquiredChannel;
            this.ownershipLock = acquiredLock;
        } catch (IOException ex) {
            releaseFailedOwnership(acquiredLock, acquiredChannel, ex);
            throw new IllegalStateException("Cannot initialize signing operation root", ex);
        } catch (RuntimeException | Error failure) {
            releaseFailedOwnership(acquiredLock, acquiredChannel, failure);
            throw failure;
        }
    }

    private static void releaseFailedOwnership(FileLock lock, FileChannel channel, Throwable failure) {
        if (lock != null) {
            try {
                lock.release();
            } catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
        }
        if (channel != null) {
            try {
                channel.close();
            } catch (IOException cleanup) {
                failure.addSuppressed(cleanup);
            }
        }
    }

    @Override
    public String id() {
        return this.id;
    }

    @Override
    public void validateSigningDomain(String namespace, Duration horizon, Duration permittedSkew) {
        if (namespace == null || !namespace.endsWith("." + id) || !operationHorizon.equals(horizon)
                || !Duration.ZERO.equals(permittedSkew)) {
            throw new IllegalArgumentException("ZeroEchoLib signing domain mismatch");
        }
        domainLock.lock();
        try {
            String current = boundNamespace.get();
            if (current != null && !current.equals(namespace)) {
                throw new IllegalArgumentException("ZeroEchoLib operation root belongs to a different signing domain");
            }
            if (current == null) {
                try {
                    writeSmallAtomic(operationRoot.resolve("DOMAIN"), namespace.getBytes(StandardCharsets.US_ASCII));
                    boundNamespace.set(namespace);
                } catch (IOException ex) {
                    throw new IllegalStateException("Cannot persist ZeroEchoLib signing domain", ex);
                }
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
     * {@link PkiId} nevertheless acts as the workflow handle through which callers
     * can query the resulting terminal {@link OperationStatus}.
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

        PkiId opId = request.submissionId();
        if (!request.namespace().endsWith("." + id)) {
            throw new IllegalArgumentException("Signing request namespace mismatch");
        }
        validateSigningDomain(request.namespace(), operationHorizon, Duration.ZERO);
        SigningSubmissionId parsed = SigningSubmissionId.parse(opId);
        purgeExpiredOperations();
        parsed.validate(request.namespace(), now(), operationHorizon, Duration.ZERO);
        if (!beginSign(request, control)) {
            return opId;
        }

        SignExecutionResult execution = null;
        try {
            execution = executeAcceptedSign(request, control);
            Instant commitTime = now();
            control.requireActive(commitTime);
            completeSign(request, execution.status);
            return opId;
        } catch (RuntimeException failure) {
            Instant stoppedAt = now();
            if (callStopped(request, control, stoppedAt)) {
                completeSign(request, stoppedSignStatus(request, control, stoppedAt));
            }
            throw failure;
        } finally {
            if (execution != null) {
                clearOwned("sign-result-copy", execution.signatureBytes);
            }
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

    private SignExecutionResult executeAcceptedSign(SignRequest request, CallControl control) {
        byte[] signatureBytes = null;
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
                return SignExecutionResult.terminal(expiredStatus());
            }
            KeyringSignatureExecutor executor = requireSignatureExecutor();
            signatureBytes = executor.sign(parts.privateAlias, resolvedAlgorithm.get(), request.content(),
                    () -> request.cancellation().isCancelled() || control.cancellation().isCancelled()
                            || !now().isBefore(control.deadline()));

            control.requireActive(now());
            Encoding outEnc = request.preferredSignatureEncoding().orElse(Encoding.BINARY);
            EncodedObject signature = encodeSignatureOrThrow(outEnc, signatureBytes);

            Instant completedAt = now();
            if (deadlineReached(request.deadline(), completedAt)) {
                return SignExecutionResult.withSignature(expiredStatus(completedAt), signatureBytes);
            }
            OperationResult result = new OperationResult(Optional.of(signature), Optional.empty());
            OperationStatus status = new OperationStatus(State.SUCCEEDED, completedAt, Optional.of(DC_SIGNED),
                    Optional.of(result));
            return SignExecutionResult.withSignature(status, signatureBytes);

        } catch (KeyringSignatureExecutor.Failure failure) {
            String detailCode = switch (failure.code()) {
                case KEY_UNAVAILABLE -> DC_KEY_NOT_FOUND;
                case ALGORITHM_MISMATCH -> DC_ALGORITHM_MISMATCH;
                case PROVIDER_FAILURE -> DC_CRYPTO_FAILURE;
            };
            if (failure.code() == KeyringSignatureExecutor.FailureCode.PROVIDER_FAILURE) {
                logSafeFailure("SIGN", detailCode, failure);
            }
            return SignExecutionResult.withSignature(failedStatus(detailCode), signatureBytes);

        } catch (InvalidRequestException inv) {
            return SignExecutionResult.withSignature(failedStatus(inv.detailCode), signatureBytes);

        } catch (KeyringSignatureExecutor.Cancellation cancelled) {
            OperationStatus status = new OperationStatus(State.CANCELLED, now(), Optional.of(DC_CANCELLED),
                    Optional.empty());
            return SignExecutionResult.withSignature(status, signatureBytes);

        } catch (IOException io) {
            logSafeFailure("SIGN", DC_KEYRING_IO_ERROR, io);
            return SignExecutionResult.withSignature(failedStatus(DC_KEYRING_IO_ERROR), signatureBytes);

        } catch (GeneralSecurityException sec) {
            logSafeFailure("SIGN", DC_CRYPTO_FAILURE, sec);
            return SignExecutionResult.withSignature(failedStatus(DC_CRYPTO_FAILURE), signatureBytes);
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
                    persistOperationRecord(operationId, event);
                }
                return false;
            }
            control.requireActive(now());
            fingerprints.put(operationId, request.semanticFingerprint());
            fences.put(operationId, request.fencingToken());
            requests.put(operationId, request);
            event = new OperationStatus(State.RUNNING, now(), Optional.of(DC_SUBMITTED), Optional.empty());
            statuses.put(operationId, event);
            persistOperationRecord(operationId, event);
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
                persistOperationRecord(operationId, committedStatus);
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
     * Signing statuses are read from the retained in-memory view loaded from the
     * durable operation root and remain available across restart until horizon
     * purge. Verification statuses are memory-only. Unknown operation identifiers
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
     * Cancellation is serialized with completion for the same signing identifier,
     * validates the fencing token, and durably records {@link State#CANCELLED}. It
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
            persistOperationRecord(operationId, cancelled);
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
     * Clears memory-resident state and releases the operation-root ownership lock.
     *
     * <p>
     * This method does not delete the underlying keyring file or durable signing
     * operation records. A subsequent provider instance reloads retained signing
     * operations and applies the documented restart recovery rules.
     * </p>
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
        try {
            this.ownershipLock.release();
            this.ownershipChannel.close();
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot release signing operation root", ex);
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

    private EncodedObject encodeSignatureOrThrow(Encoding encoding, byte[] sigBytes) throws InvalidRequestException {
        if (encoding == Encoding.BINARY || encoding == Encoding.DER) {
            return new EncodedObject(encoding, sigBytes);
        }
        if (encoding == Encoding.PEM) {
            String pem = pemWrap("ZEROECHO SIGNATURE", sigBytes);
            byte[] encoded = pem.getBytes(StandardCharsets.US_ASCII);
            try {
                return new EncodedObject(Encoding.PEM, encoded);
            } finally {
                clearOwned("sign-encoded-result", encoded);
            }
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
        if (this.fingerprints.containsKey(id)) {
            persistOperationRecord(id, st);
        }
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

    private long loadTimeWatermark() throws IOException {
        Path path = operationRoot.resolve("TIME_WATERMARK");
        long observed = clock.instant().toEpochMilli();
        if (!Files.exists(path)) {
            writeSmallAtomic(path, Long.toString(observed).getBytes(StandardCharsets.US_ASCII));
            return observed;
        }
        try {
            return Math.max(observed, Long.parseLong(Files.readString(path, StandardCharsets.US_ASCII).trim()));
        } catch (NumberFormatException ex) {
            throw new IllegalStateException("Invalid provider time watermark", ex);
        }
    }

    private Instant now() {
        timeWatermarkLock.lock();
        try {
            long monotonic = Math.max(timeWatermark.get(), clock.instant().toEpochMilli());
            try {
                writeSmallAtomic(operationRoot.resolve("TIME_WATERMARK"),
                        Long.toString(monotonic).getBytes(StandardCharsets.US_ASCII));
            } catch (IOException ex) {
                throw new IllegalStateException("Cannot persist provider time watermark", ex);
            }
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
                        Files.deleteIfExists(operationRecordPath(operationId));
                    }
                } catch (IOException ex) {
                    throw new IllegalStateException("Cannot purge expired provider signing operation", ex);
                } finally {
                    releaseOperationLock(operationId, lock);
                }
            }
        }
    }

    private static void writeSmallAtomic(Path target, byte[] data) throws IOException {
        Files.createDirectories(target.getParent());
        Path temporary = Files.createTempFile(target.getParent(), "." + target.getFileName(), ".tmp");
        try {
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer bytes = ByteBuffer.wrap(data);
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
            restrictPermissions(target, false);
            try (FileChannel directory = FileChannel.open(target.getParent(), StandardOpenOption.READ)) {
                directory.force(true);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static void restrictPermissions(Path path, boolean directory) throws IOException {
        try {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"));
        } catch (UnsupportedOperationException ex) {
            // Non-POSIX platforms rely on their native access-control mechanism.
            if (LOG.isLoggable(Level.FINEST)) {
                LOG.log(Level.FINEST, "Filesystem permission adjustment unavailable: code={0}, exception={1}",
                        new Object[] { "POSIX_UNAVAILABLE", ex.getClass().getName() });
            }
        }
    }

    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private void loadOperationRecords() throws IOException {
        Path records = this.operationRoot.resolve("records");
        if (!Files.isDirectory(records)) {
            return;
        }
        try (java.util.stream.Stream<Path> paths = Files.list(records)) {
            for (Path path : paths.filter(Files::isRegularFile).toList()) {
                try (DataInputStream input = new DataInputStream(Files.newInputStream(path))) {
                    int version = input.readInt();
                    if (version != OPERATION_RECORD_VERSION && version != PREVIOUS_OPERATION_RECORD_VERSION) {
                        throw new IllegalStateException("Unsupported signing operation record version");
                    }
                    PkiId operationId = new PkiId(input.readUTF());
                    SigningSubmissionId parsedId = SigningSubmissionId.parse(operationId);
                    String fingerprint = input.readUTF();
                    long fence = input.readLong();
                    Optional<String> cancellationReason = version == OPERATION_RECORD_VERSION && input.readBoolean()
                            ? Optional.of(input.readUTF()) : Optional.empty();
                    SignRequest request = readSignRequest(input);
                    if (!operationId.equals(request.submissionId())
                            || !constantTimeEquals(fingerprint, request.semanticFingerprint())
                            || !parsedId.namespace().equals(request.namespace())
                            || !operationRecordPath(operationId).equals(path)) {
                        throw new IllegalStateException("Signing operation record identity mismatch");
                    }
                    State state = stateFromCode(input.readInt());
                    Instant updatedAt = Instant.ofEpochSecond(input.readLong(), input.readInt());
                    Optional<String> detail = input.readBoolean() ? Optional.of(input.readUTF()) : Optional.empty();
                    Optional<OperationResult> result = readOperationResult(input);
                    if (input.available() != 0) {
                        throw new IllegalStateException("Trailing data in signing operation record");
                    }
                    if (state == State.SUCCEEDED != result.isPresent()) {
                        throw new IllegalStateException("Signing operation record result/state mismatch");
                    }
                    OperationStatus loaded = new OperationStatus(state, updatedAt, detail, result);
                    boolean repaired = false;
                    if (state == State.SUCCEEDED && (updatedAt.isBefore(parsedId.createdAt())
                            || deadlineReached(request.deadline(), updatedAt))) {
                        loaded = expiredStatus(updatedAt);
                        repaired = true;
                    }
                    if (state == State.RUNNING) {
                        loaded = new OperationStatus(State.FAILED, now(), Optional.of("RECOVERY_INCOMPLETE"),
                                Optional.empty());
                        repaired = true;
                    }
                    this.fingerprints.put(operationId, fingerprint);
                    this.fences.put(operationId, fence);
                    cancellationReason.ifPresent(value -> this.cancellationReasons.put(operationId, value));
                    this.requests.put(operationId, request);
                    this.statuses.put(operationId, loaded);
                    if (repaired) {
                        persistOperationRecord(operationId, loaded);
                    }
                }
            }
        }
    }

    private void persistOperationRecord(PkiId operationId, OperationStatus status) {
        WipeableByteArrayOutputStream bytes = new WipeableByteArrayOutputStream();
        byte[] encodedRecord = null;
        try {
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                output.writeInt(OPERATION_RECORD_VERSION);
                output.writeUTF(operationId.value());
                output.writeUTF(this.fingerprints.get(operationId));
                output.writeLong(this.fences.getOrDefault(operationId, 0L));
                output.writeBoolean(this.cancellationReasons.containsKey(operationId));
                if (this.cancellationReasons.containsKey(operationId)) {
                    output.writeUTF(this.cancellationReasons.get(operationId));
                }
                writeSignRequest(output, requests.get(operationId));
                output.writeInt(stateCode(status.state()));
                output.writeLong(status.updatedAt().getEpochSecond());
                output.writeInt(status.updatedAt().getNano());
                output.writeBoolean(status.detailCode().isPresent());
                if (status.detailCode().isPresent()) {
                    output.writeUTF(status.detailCode().orElseThrow());
                }
                writeOperationResult(output, status.result());
            }
            encodedRecord = bytes.toByteArray();
            Path records = this.operationRoot.resolve("records");
            Files.createDirectories(records);
            restrictPermissions(records, true);
            Path target = operationRecordPath(operationId);
            Path temporary = Files.createTempFile(records, ".operation-", ".tmp");
            try {
                try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                    channel.write(ByteBuffer.wrap(encodedRecord));
                    channel.force(true);
                }
                try {
                    Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                } catch (AtomicMoveNotSupportedException ex) {
                    Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
                }
                restrictPermissions(target, false);
                try (FileChannel directory = FileChannel.open(records, StandardOpenOption.READ)) {
                    directory.force(true);
                }
            } finally {
                Files.deleteIfExists(temporary);
            }
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot persist signing operation status", ex);
        } finally {
            clearOwned("persisted-operation-copy", encodedRecord);
            bytes.wipe();
        }
    }

    private Path operationRecordPath(PkiId operationId) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(operationId.value().getBytes(StandardCharsets.UTF_8));
            return this.operationRoot.resolve("records").resolve(HexFormat.of().formatHex(digest) + ".bin");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
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

    private void writeSignRequest(DataOutputStream output, SignRequest request) throws IOException {
        if (request == null) {
            throw new IllegalStateException("Missing signing request snapshot");
        }
        output.writeUTF(request.submissionId().value());
        output.writeUTF(request.namespace());
        output.writeUTF(request.accessContext().principal().type());
        output.writeUTF(request.accessContext().principal().name());
        output.writeUTF(request.accessContext().purpose().value());
        output.writeBoolean(request.accessContext().objectId().isPresent());
        if (request.accessContext().objectId().isPresent()) {
            output.writeUTF(request.accessContext().objectId().orElseThrow().value());
        }
        output.writeBoolean(request.accessContext().formatId().isPresent());
        if (request.accessContext().formatId().isPresent()) {
            output.writeUTF(request.accessContext().formatId().orElseThrow().value());
        }
        output.writeUTF(request.keyRef().value());
        output.writeUTF(request.algorithmId());
        output.writeUTF(request.content().contentId());
        output.writeLong(request.content().length().orElse(-1L));
        output.writeBoolean(request.preferredSignatureEncoding().isPresent());
        if (request.preferredSignatureEncoding().isPresent()) {
            output.writeInt(encodingCode(request.preferredSignatureEncoding().orElseThrow()));
        }
        output.writeBoolean(request.deadline().isPresent());
        if (request.deadline().isPresent()) {
            Instant deadline = request.deadline().orElseThrow();
            output.writeLong(deadline.getEpochSecond());
            output.writeInt(deadline.getNano());
        }
    }

    private SignRequest readSignRequest(DataInputStream input) throws IOException {
        PkiId submissionId = new PkiId(input.readUTF());
        String namespace = input.readUTF();
        zeroecho.pki.api.audit.Principal principal = new zeroecho.pki.api.audit.Principal(input.readUTF(),
                input.readUTF());
        zeroecho.pki.api.audit.Purpose purpose = new zeroecho.pki.api.audit.Purpose(input.readUTF());
        Optional<PkiId> objectId = input.readBoolean() ? Optional.of(new PkiId(input.readUTF())) : Optional.empty();
        Optional<zeroecho.pki.api.FormatId> formatId = input.readBoolean()
                ? Optional.of(new zeroecho.pki.api.FormatId(input.readUTF()))
                : Optional.empty();
        zeroecho.pki.api.audit.AccessContext access = new zeroecho.pki.api.audit.AccessContext(principal, purpose,
                objectId, formatId);
        KeyRef keyRef = new KeyRef(input.readUTF());
        String algorithmId = input.readUTF();
        String contentId = input.readUTF();
        long contentLength = input.readLong();
        if (contentId.isBlank() || contentLength < -1L) {
            throw new IllegalStateException("Invalid persisted signing content metadata");
        }
        Optional<Encoding> preferred = input.readBoolean() ? Optional.of(encodingFromCode(input.readInt()))
                : Optional.empty();
        Optional<Instant> deadline = input.readBoolean()
                ? Optional.of(Instant.ofEpochSecond(input.readLong(), input.readInt()))
                : Optional.empty();
        return SignRequest.create(submissionId, namespace, 1L, access, keyRef, algorithmId,
                new RecoveredContentMetadata(contentId, contentLength), preferred, deadline);
    }

    /**
     * Metadata-only view retained for terminal request identity after restart.
     * Recovered non-terminal operations fail closed before this content can execute.
     */
    private record RecoveredContentMetadata(String contentId, long persistedLength) implements RepeatableContent {
        @Override
        public InputStream openStream() throws IOException {
            throw new IOException("Recovered content requires staged-content resolution");
        }

        @Override
        public java.util.OptionalLong length() {
            return persistedLength < 0L ? java.util.OptionalLong.empty() : java.util.OptionalLong.of(persistedLength);
        }

        @Override
        public void close() {
            // Metadata owns no live resource.
        }
    }

    private static Encoding encodingFromCode(int code) {
        return switch (code) {
            case 10 -> Encoding.DER;
            case 20 -> Encoding.PEM;
            case 30 -> Encoding.BINARY;
            default -> throw new IllegalStateException("Invalid persisted encoding code");
        };
    }

    private static int encodingCode(Encoding encoding) {
        return switch (encoding) {
            case DER -> 10;
            case PEM -> 20;
            case BINARY -> 30;
        };
    }

    private static int stateCode(State state) {
        return switch (state) {
            case PENDING -> 10;
            case WAITING_APPROVAL -> 20;
            case RUNNING -> 30;
            case SUCCEEDED -> 40;
            case FAILED -> 50;
            case CANCELLED -> 60;
            case EXPIRED -> 70;
        };
    }

    private static State stateFromCode(int code) {
        return switch (code) {
            case 10 -> State.PENDING;
            case 20 -> State.WAITING_APPROVAL;
            case 30 -> State.RUNNING;
            case 40 -> State.SUCCEEDED;
            case 50 -> State.FAILED;
            case 60 -> State.CANCELLED;
            case 70 -> State.EXPIRED;
            default -> throw new IllegalStateException("Invalid persisted signing state code");
        };
    }

    private void writeOperationResult(DataOutputStream output, Optional<OperationResult> result) throws IOException {
        output.writeBoolean(result.isPresent());
        if (result.isEmpty()) {
            return;
        }
        OperationResult value = result.orElseThrow();
        output.writeBoolean(value.signature().isPresent());
        if (value.signature().isPresent()) {
            EncodedObject signature = value.signature().orElseThrow();
            output.writeInt(encodingCode(signature.encoding()));
            byte[] signatureBytes = signature.bytes();
            try {
                output.writeInt(signatureBytes.length);
                output.write(signatureBytes);
            } finally {
                clearOwned("persisted-signature-result", signatureBytes);
            }
        }
        output.writeBoolean(value.verified().isPresent());
        if (value.verified().isPresent()) {
            output.writeBoolean(value.verified().orElseThrow());
        }
    }

    private Optional<OperationResult> readOperationResult(DataInputStream input) throws IOException {
        if (!input.readBoolean()) {
            return Optional.empty();
        }
        Optional<EncodedObject> signature = Optional.empty();
        if (input.readBoolean()) {
            Encoding encoding = encodingFromCode(input.readInt());
            int length = input.readInt();
            if (length < 0 || length > 16 * 1024 * 1024) {
                throw new IllegalStateException("Invalid persisted signature length");
            }
            byte[] signatureBytes = input.readNBytes(length);
            try {
                if (signatureBytes.length != length) {
                    throw new IllegalStateException("Truncated persisted signature");
                }
                signature = Optional.of(new EncodedObject(encoding, signatureBytes));
            } finally {
                clearOwned("loaded-signature-result", signatureBytes);
            }
        }
        Optional<Boolean> verification = input.readBoolean() ? Optional.of(input.readBoolean()) : Optional.empty();
        return Optional.of(new OperationResult(signature, verification));
    }

    private static PkiId newOperationId() {
        return new PkiId(UUID.randomUUID().toString());
    }

    /**
     * Output stream whose retained serialized signing material can be overwritten.
     */
    private final class WipeableByteArrayOutputStream extends ByteArrayOutputStream {
        private void wipe() {
            clearOwned("persisted-operation-buffer", buf);
            reset();
        }
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
    private static final class SignExecutionResult {
        private final OperationStatus status;
        private final byte[] signatureBytes;

        private SignExecutionResult(OperationStatus status, byte[] signatureBytes) {
            this.status = status;
            this.signatureBytes = signatureBytes;
        }

        private static SignExecutionResult terminal(OperationStatus status) {
            return new SignExecutionResult(status, null);
        }

        private static SignExecutionResult withSignature(OperationStatus status, byte[] signatureBytes) {
            return new SignExecutionResult(status, signatureBytes);
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
