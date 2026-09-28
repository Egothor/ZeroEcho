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
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BiConsumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.alg.common.sig.SignatureInteropProfiles;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringSignatureExecutor;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.sdk.ZeroEchoSession;

/**
 * Inline ZeroEcho-lib signing provider.
 *
 * <p>The provider retains only configured keyring resources and O(1) domain
 * state. It has no per-operation request, status, fingerprint, fence or
 * cancellation maps. The store must durably claim a dispatch before calling
 * {@link #dispatch(SignRequest, CallControl)}. If the process loses an inline
 * call, {@link #reconcile(PkiId, CallControl)} reports a terminal unrecoverable
 * observation and never repeats cryptography.</p>
 */
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.AvoidCatchingGenericException" })
public final class ZeroEchoLibSigningProvider implements SigningProvider, PublicKeyInfoSource {
    private static final long NO_FENCE = 0L;
    private static final Logger LOG = Logger.getLogger(ZeroEchoLibSigningProvider.class.getName());

    private final String id;
    private final Path keyringPath;
    private final Clock clock;
    private final Duration operationHorizon;
    private final String keyRefPrefix;
    private final boolean requireComponentSuffix;
    private final ConfigurationCommitment configurationCommitment;
    private final ZeroEchoSession session;
    private final KeyringUnlockProvider keyringUnlockProvider;
    private final BiConsumer<String, byte[]> cleanupObserver;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final ReentrantLock domainLock = new ReentrantLock();

    private volatile KeyringStore keyringOrNull; // NOPMD
    private String boundNamespace;
    private boolean closed;

    /* default */ ZeroEchoLibSigningProvider(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider unlockProvider, ConfigurationCommitment commitment) {
        this(id, keyringPath, standaloneScope, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                unlockProvider, (category, cleared) -> { }, new ZeroEchoSession(), commitment);
    }

    /* default */ ZeroEchoLibSigningProvider(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider unlockProvider, KeyringStore keyring) {
        this(id, keyringPath, standaloneScope, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                unlockProvider, (category, cleared) -> { }, new ZeroEchoSession(),
                configurationCommitment(keyring, id, operationHorizon, keyRefPrefix, requireComponentSuffix));
        keyringOrNull = Objects.requireNonNull(keyring, "keyring must not be null");
    }

    @SuppressWarnings("PMD.ExcessiveParameterList")
    /* default */ ZeroEchoLibSigningProvider(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider unlockProvider, BiConsumer<String, byte[]> cleanupObserver,
            ConfigurationCommitment commitment) {
        this(id, keyringPath, standaloneScope, clock, operationHorizon, keyRefPrefix, requireComponentSuffix,
                unlockProvider, cleanupObserver, new ZeroEchoSession(), commitment);
    }

    private ZeroEchoLibSigningProvider(String id, Path keyringPath, Path standaloneScope, Clock clock,
            Duration operationHorizon, String keyRefPrefix, boolean requireComponentSuffix,
            KeyringUnlockProvider unlockProvider, BiConsumer<String, byte[]> cleanupObserver,
            ZeroEchoSession session, ConfigurationCommitment commitment) {
        Objects.requireNonNull(standaloneScope, "standaloneScope must not be null");
        if (id == null || id.isBlank() || keyringPath == null || clock == null
                || operationHorizon == null || operationHorizon.isZero() || operationHorizon.isNegative()
                || keyRefPrefix == null || unlockProvider == null || cleanupObserver == null) {
            throw new IllegalArgumentException("Signing provider configuration is invalid");
        }
        this.id = id;
        this.keyringPath = keyringPath;
        this.clock = clock;
        this.operationHorizon = operationHorizon;
        this.keyRefPrefix = keyRefPrefix;
        this.requireComponentSuffix = requireComponentSuffix;
        this.keyringUnlockProvider = unlockProvider;
        this.cleanupObserver = cleanupObserver;
        this.session = Objects.requireNonNull(session, "session must not be null");
        this.configurationCommitment = inputCapabilities().commitment(
                Objects.requireNonNull(commitment, "commitment must not be null"), supportedAlgorithms());
    }

    @Override
    public String id() {
        return id;
    }

    @Override
    public ConfigurationCommitment configurationCommitment() {
        return configurationCommitment;
    }

    @Override
    public zeroecho.pki.spi.crypto.SigningInputCapabilities inputCapabilities() {
        return new zeroecho.pki.spi.crypto.SigningInputCapabilities(Long.MAX_VALUE, java.util.Map.of());
    }

    @Override
    public Set<String> supportedAlgorithms() {
        Set<String> supported = new java.util.LinkedHashSet<>(session.available());
        supported.addAll(SignatureInteropProfiles.algorithmIds());
        return Collections.unmodifiableSet(supported);
    }

    @Override
    public void validateSigningDomain(String namespace, Duration horizon, Duration permittedSkew) {
        String expectedSuffix = "." + id;
        if (namespace == null || !namespace.endsWith(expectedSuffix) || !operationHorizon.equals(horizon)
                || !Duration.ZERO.equals(permittedSkew)) {
            throw new IllegalArgumentException("ZeroEchoLib signing domain mismatch");
        }
        domainLock.lock();
        try {
            if (boundNamespace != null && !boundNamespace.equals(namespace)) {
                throw new IllegalArgumentException("ZeroEchoLib provider belongs to a different signing domain");
            }
            boundNamespace = namespace;
        } finally {
            domainLock.unlock();
        }
    }

    @Override
    public OperationObservation dispatch(SignRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(control, "control").requireActive(now());
        requireExactDomain(request);
        if (!configurationCommitment.matches(request.configurationCommitment())) {
            throw new IllegalArgumentException("Signing provider configuration commitment mismatch");
        }
        byte[] signatureBytes = null;
        try {
            KeyRefParts parts = parseKeyRef(request.keyRef());
            Optional<AlgorithmIdentity> algorithm = BootstrapAlgorithmIdentities.resolve(request.algorithmId());
            if (algorithm.isEmpty() || algorithm.orElseThrow().kind() != AlgorithmIdentity.Kind.SIGNATURE) {
                return failure(request.operationId(), DetailCode.INVALID_ALGORITHM);
            }
            control.requireActive(now());
            if (deadlineReached(request.deadline(), now())) {
                return failure(request.operationId(), DetailCode.DEADLINE_EXPIRED);
            }
            KeyringSignatureExecutor executor = new KeyringSignatureExecutor(requireKeyring(), session);
            try (CommittedContent content = new CommittedContent(request.content(), request.contentCommitment())) {
                signatureBytes = executor.sign(parts.privateAlias, algorithm.orElseThrow(), content,
                        () -> request.cancellation().isCancelled() || control.cancellation().isCancelled()
                                || !now().isBefore(control.deadline()));
            }
            control.requireActive(now());
            try (OwnedEncodedSignature encodedSignature = encode(
                    request.preferredSignatureEncoding().orElse(Encoding.BINARY), signatureBytes)) {
                if (encodedSignature.reuses(signatureBytes)) {
                    signatureBytes = null;
                }
                Instant completedAt = now();
                if (deadlineReached(request.deadline(), completedAt)) {
                    return failure(request.operationId(), DetailCode.DEADLINE_EXPIRED);
                }
                byte[] encoded = encodedSignature.transfer();
                try {
                    return new OperationObservation(request.operationId(), ObservationState.SUCCEEDED, completedAt,
                            DetailCode.SIGNED, Optional.of(new EncodedObject(encodedSignature.encoding, encoded)));
                } finally {
                    clearOwned("sign-result", encoded);
                }
            }
        } catch (InvalidRequestException invalid) {
            return failure(request.operationId(), invalid.detailCode);
        } catch (KeyringSignatureExecutor.Failure failure) {
            DetailCode code = switch (failure.code()) {
                case KEY_UNAVAILABLE -> DetailCode.KEY_NOT_FOUND;
                case ALGORITHM_MISMATCH -> DetailCode.ALGORITHM_MISMATCH;
                case PROVIDER_FAILURE -> DetailCode.CRYPTO_FAILURE;
            };
            logSafeFailure(code, failure);
            return failure(request.operationId(), code);
        } catch (KeyringSignatureExecutor.Cancellation cancelled) {
            return new OperationObservation(request.operationId(), ObservationState.CANCELLED, now(),
                    DetailCode.CANCELLED, Optional.empty());
        } catch (ContentIntegrityException invalidContent) {
            logSafeFailure(DetailCode.CONTENT_INTEGRITY_FAILURE, invalidContent);
            return failure(request.operationId(), DetailCode.CONTENT_INTEGRITY_FAILURE);
        } catch (IOException failure) {
            logSafeFailure(DetailCode.KEYRING_IO_FAILURE, failure);
            return failure(request.operationId(), DetailCode.KEYRING_IO_FAILURE);
        } catch (GeneralSecurityException failure) {
            logSafeFailure(DetailCode.CRYPTO_FAILURE, failure);
            return failure(request.operationId(), DetailCode.CRYPTO_FAILURE);
        } finally {
            clearOwned("sign-raw", signatureBytes);
        }
    }

    @Override
    public OperationObservation reconcile(PkiId operationId, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(control, "control").requireActive(now());
        return new OperationObservation(operationId, ObservationState.UNRECOVERABLE, now(),
                DetailCode.LOCAL_RESTART_UNRECOVERABLE, Optional.empty());
    }

    @Override
    public OperationObservation cancel(PkiId operationId, long fencingToken, CancellationReason reason,
            CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(control, "control").requireActive(now());
        if (fencingToken <= NO_FENCE) {
            throw new IllegalArgumentException("fencingToken must be positive");
        }
        return new OperationObservation(operationId, ObservationState.UNRECOVERABLE, now(),
                DetailCode.LOCAL_RESTART_UNRECOVERABLE, Optional.empty());
    }

    /**
     * Visits private-key references already known by this local keyring without opening private key material.
     * The keyring alias snapshot is bounded by its existing entry limit; callbacks are never retained.
     * Duplicate logical aliases may be visited and must be deduplicated by a collecting caller.
     * @param visitor consumer of canonical non-secret key references
     * @throws IllegalStateException when the keyring is unavailable
     */
    // The provider owns the borrowed keyring; closing it during enumeration would invalidate subsequent signing.
    // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
    // Untrusted input/provider diagnostics are deliberately excluded from the safe boundary exception.
    @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.CloseResource", "PMD.PreserveStackTrace" })
    public void visitKnownKeyReferences(java.util.function.Consumer<KeyRef> visitor) {
        Objects.requireNonNull(visitor, "visitor");
        try {
            KeyringStore keyring = requireKeyring();
            for (String alias : keyring.aliases()) {
                if (keyring.contains(alias + ".prv")) { visitor.accept(new KeyRef(keyRefPrefix + alias + ".prv")); }
            }
        } catch (IOException | GeneralSecurityException failure) {
            throw new IllegalStateException("Local key metadata is unavailable");
        }
    }

    @Override
    public EncodedObject resolvePublicKeyInfo(KeyRef keyRef) {
        Objects.requireNonNull(keyRef, "keyRef");
        try {
            KeyRefParts parts = parseKeyRef(keyRef);
            String privateAlias = parts.privateAlias;
            String logicalAlias = privateAlias.endsWith(".prv")
                    ? privateAlias.substring(0, privateAlias.length() - 4) : privateAlias;
            PublicKey publicKey = requireKeyring().getPublic(logicalAlias);
            return new EncodedObject(Encoding.DER, publicKey.getEncoded());
        } catch (InvalidRequestException | IOException | GeneralSecurityException failure) {
            throw new PkiException("Managed public key resolution failed: code=PUBLIC_KEY_RESOLUTION_FAILED", failure);
        }
    }

    @Override
    @SuppressWarnings("PMD.CloseResource")
    public void close() {
        KeyringStore keyring;
        lifecycleLock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
            keyring = keyringOrNull;
            keyringOrNull = null;
        } finally {
            lifecycleLock.unlock();
        }
        if (keyring != null) {
            keyring.close();
        }
    }

    private void requireExactDomain(SignRequest request) {
        domainLock.lock();
        try {
            if (boundNamespace == null || !boundNamespace.equals(request.namespace())) {
                throw new IllegalArgumentException("Signing request namespace mismatch");
            }
        } finally {
            domainLock.unlock();
        }
    }

    private OperationObservation failure(PkiId operationId, DetailCode code) {
        ObservationState state = code == DetailCode.DEADLINE_EXPIRED
                ? ObservationState.FAILED : ObservationState.FAILED;
        return new OperationObservation(operationId, state, now(), code, Optional.empty());
    }

    private KeyringStore requireKeyring() throws IOException, GeneralSecurityException {
        lifecycleLock.lock();
        try {
            if (closed) {
                throw new IOException("Signing provider is closed");
            }
            KeyringStore existing = keyringOrNull;
            if (existing != null) {
                return existing;
            }
            try (KeyringPassword password = acquirePassword()) {
                KeyringStore loaded = KeyringStore.open(keyringPath, password);
                if (closed) {
                    loaded.close();
                    throw new IOException("Signing provider is closed");
                }
                keyringOrNull = loaded;
                return loaded;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    private KeyringPassword acquirePassword() throws IOException {
        KeyringPassword password = keyringUnlockProvider.acquire();
        if (password == null) {
            throw new IOException("Keyring unlock provider returned no password");
        }
        return password;
    }

    private KeyRefParts parseKeyRef(KeyRef keyRef) throws InvalidRequestException {
        String raw = keyRef.value();
        if (!raw.startsWith(keyRefPrefix)) {
            throw new InvalidRequestException(DetailCode.INVALID_KEY_REFERENCE);
        }
        String suffix = raw.substring(keyRefPrefix.length());
        boolean privateSuffix = suffix.endsWith(".prv");
        if (requireComponentSuffix && !privateSuffix) {
            throw new InvalidRequestException(DetailCode.INVALID_KEY_REFERENCE);
        }
        return new KeyRefParts(privateSuffix ? suffix : suffix + ".prv");
    }

    private OwnedEncodedSignature encode(Encoding encoding, byte[] signature) throws InvalidRequestException {
        if (encoding == Encoding.BINARY || encoding == Encoding.DER) {
            return new OwnedEncodedSignature(encoding, signature);
        }
        if (encoding == Encoding.PEM) {
            String base64 = Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(signature);
            String pem = "-----BEGIN ZEROECHO SIGNATURE-----\n" + base64
                    + "\n-----END ZEROECHO SIGNATURE-----\n";
            return new OwnedEncodedSignature(Encoding.PEM, pem.getBytes(StandardCharsets.US_ASCII));
        }
        throw new InvalidRequestException(DetailCode.UNSUPPORTED_SIGNATURE_ENCODING);
    }

    private Instant now() {
        return clock.instant();
    }

    private static boolean deadlineReached(Optional<Instant> deadline, Instant now) {
        return deadline.isPresent() && !now.isBefore(deadline.orElseThrow());
    }

    private static ConfigurationCommitment configurationCommitment(KeyringStore keyring, String id,
            Duration horizon, String prefix, boolean requireSuffix) {
        byte[] tag = null;
        try {
            tag = keyring.zeroEchoSigningConfigurationTag(id, horizon, prefix, requireSuffix);
            return new ConfigurationCommitment(tag);
        } catch (GeneralSecurityException failure) {
            throw new IllegalStateException("ZEROECHO_SIGNING_CONFIGURATION_COMMITMENT_FAILED", failure);
        } finally {
            if (tag != null) {
                Arrays.fill(tag, (byte) 0);
            }
        }
    }

    private static void logSafeFailure(DetailCode code, Throwable failure) {
        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "Signing provider failed: code={0}, exception={1}",
                    new Object[] { code, failure.getClass().getName() });
        }
    }

    private void clearOwned(String category, byte[] bytes) {
        if (bytes != null) {
            Arrays.fill(bytes, (byte) 0);
            cleanupObserver.accept(category, bytes);
        }
    }

    private record KeyRefParts(String privateAlias) { }

    /** Owns one encoded signature until its bytes are transferred. */
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

        @SuppressWarnings("PMD.CompareObjectsWithEquals")
        private boolean reuses(byte[] candidate) {
            return bytes == candidate;
        }

        @Override
        public void close() {
            clearOwned("sign-encoded", bytes);
            bytes = null;
        }
    }

    /** Verifies the exact content commitment while cryptography consumes it. */
    private static final class CommittedContent implements RepeatableContent {
        private final RepeatableContent delegate;
        private final ContentCommitment commitment;
        private final AtomicBoolean opened = new AtomicBoolean();

        private CommittedContent(RepeatableContent delegate, ContentCommitment commitment) {
            this.delegate = Objects.requireNonNull(delegate, "delegate");
            this.commitment = Objects.requireNonNull(commitment, "commitment");
        }

        @Override
        public InputStream openStream() throws IOException {
            if (!opened.compareAndSet(false, true)) {
                throw new ContentIntegrityException();
            }
            try {
                return new CommitmentInputStream(delegate.openStream(), commitment);
            } catch (RuntimeException failure) {
                throw new ContentIntegrityException(failure);
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
            // Caller retains the durable content handle.
        }
    }

    /** Streaming commitment verifier around the borrowed payload stream. */
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
            int value = readDelegate();
            if (value < 0) {
                validateAtEnd();
            } else {
                digest.update((byte) value);
                count = Math.addExact(count, 1L);
                rejectExcess();
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            int read = readDelegate(bytes, offset, length);
            if (read < 0) {
                validateAtEnd();
            } else if (read > 0) {
                digest.update(bytes, offset, read);
                count = Math.addExact(count, read);
                rejectExcess();
            }
            return read;
        }

        private int readDelegate() throws IOException {
            try {
                return super.read();
            } catch (java.io.InterruptedIOException interrupted) {
                throw interrupted;
            } catch (IOException failure) {
                throw new ContentIntegrityException();
            }
        }

        private int readDelegate(byte[] bytes, int offset, int length) throws IOException {
            try {
                return super.read(bytes, offset, length);
            } catch (java.io.InterruptedIOException interrupted) {
                throw interrupted;
            } catch (IOException failure) {
                throw new ContentIntegrityException();
            }
        }

        private void rejectExcess() throws ContentIntegrityException {
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

    /** Safe internal classification for candidate-content integrity failures. */
    private static final class ContentIntegrityException extends IOException {
        private static final long serialVersionUID = 1L;

        private ContentIntegrityException() {
            super();
        }

        private ContentIntegrityException(Throwable cause) {
            super(cause);
        }
    }

    /** Safe internal validation failure carrying only a finite detail code. */
    private static final class InvalidRequestException extends Exception {
        private static final long serialVersionUID = 1L;
        private final DetailCode detailCode;

        private InvalidRequestException(DetailCode detailCode) {
            super();
            this.detailCode = detailCode;
        }
    }
}
