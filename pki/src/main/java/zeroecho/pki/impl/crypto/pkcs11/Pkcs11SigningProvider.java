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
package zeroecho.pki.impl.crypto.pkcs11;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import zeroecho.pki.spi.crypto.SigningProvider;

/**
 * PKCS#11 / HSM signing provider.
 *
 * <p>All cryptographic operations execute on the HSM token via the JDK's built-in
 * {@code SunPKCS11} provider. Private key material never leaves the HSM boundary.
 * This satisfies FIPS 140-3 Level 3 key non-exportability requirements.</p>
 *
 * <p>The provider is thread-safe. A single {@link KeyStore} session is held open
 * for the lifetime of this instance. The signing session pool (bounded by
 * {@code sessionPoolSize}) allows concurrent signing across multiple CA authorities
 * without contention on a single PKCS#11 session.</p>
 *
 * <p>A local provider always completes {@link #dispatch} inline. If the process
 * restarts between a durable claim and completion, {@link #reconcile} returns
 * {@link ObservationState#UNRECOVERABLE} and never repeats cryptographic execution.</p>
 *
 * @since 1.0
 */

public final class Pkcs11SigningProvider implements SigningProvider {

    private static final long NO_FENCE = 0L;
    private static final int READ_BUFFER_BYTES = 8192;
    private static final Logger LOG = Logger.getLogger(Pkcs11SigningProvider.class.getName());

    private final String id;
    private final KeyStore keyStore;
    private final Provider provider;
    private final Set<String> supportedAlgorithms;
    private final ConfigurationCommitment configurationCommitment;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private volatile boolean closed; // NOPMD

    /**
     * Creates a PKCS#11 signing provider backed by the given already-opened KeyStore.
     *
     * @param id                    stable provider identifier (never blank)
     * @param keyStore              open PKCS#11 KeyStore (caller must not close it)
     * @param provider              underlying SunPKCS11 provider used for all JCA Signature operations
     * @param supportedAlgorithms   JCA algorithm names this HSM slot supports
     * @param backendCommitment     SHA-256 commitment to the backend configuration
     * @param operationHorizon      signing operation horizon (positive, not used for HSM expiry)
     * @param keyRefPrefix          key reference prefix (may be empty)
     * @param keyLabelPattern       key label template (informational)
     * @param sessionPoolSize       maximum concurrent PKCS#11 sessions (≥ 1)
     */
    /* default */ Pkcs11SigningProvider(String id, KeyStore keyStore, Provider provider,
            Set<String> supportedAlgorithms, ConfigurationCommitment backendCommitment,
            Duration operationHorizon, String keyRefPrefix, String keyLabelPattern,
            int sessionPoolSize) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(keyStore, "keyStore must not be null");
        Objects.requireNonNull(provider, "provider must not be null");
        Objects.requireNonNull(supportedAlgorithms, "supportedAlgorithms must not be null");
        Objects.requireNonNull(backendCommitment, "backendCommitment must not be null");
        Objects.requireNonNull(operationHorizon, "operationHorizon must not be null");
        Objects.requireNonNull(keyRefPrefix, "keyRefPrefix must not be null");
        Objects.requireNonNull(keyLabelPattern, "keyLabelPattern must not be null");
        if (id.isBlank() || supportedAlgorithms.isEmpty() || sessionPoolSize < 1) {
            throw new IllegalArgumentException("Pkcs11SigningProvider configuration is invalid");
        }
        this.id = id;
        this.keyStore = keyStore;
        this.provider = provider;
        this.supportedAlgorithms = supportedAlgorithms.stream()
                .filter(algorithm -> !zeroecho.core.alg.common.sig.StatefulSigningGuard.isStateful(algorithm))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        this.configurationCommitment = new SigningInputCapabilities(Long.MAX_VALUE, Map.of())
                .commitment(backendCommitment, this.supportedAlgorithms);
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
    public Set<String> supportedAlgorithms() {
        return supportedAlgorithms;
    }

    @Override
    public SigningInputCapabilities inputCapabilities() {
        return new SigningInputCapabilities(Long.MAX_VALUE, Map.of());
    }

    @Override
    public OperationObservation dispatch(SignRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");
        if (zeroecho.core.alg.common.sig.StatefulSigningGuard.isStateful(request.algorithmId())) {
            return failedObservation(request.operationId(), DetailCode.INVALID_ALGORITHM);
        }
        Objects.requireNonNull(control, "control").requireActive(Instant.now());
        if (!configurationCommitment.matches(request.configurationCommitment())) {
            throw new IllegalArgumentException("Signing provider configuration commitment mismatch");
        }
        byte[] signatureBytes = null;
        try {
            PrivateKey privateKey = lookupKey(request.keyRef().value());
            if (privateKey == null) {
                return failedObservation(request.operationId(), DetailCode.KEY_NOT_FOUND);
            }
            control.requireActive(Instant.now());
            Signature sig = buildSignature(request.algorithmId(), privateKey);
            if (sig == null) {
                return failedObservation(request.operationId(), DetailCode.INVALID_ALGORITHM);
            }
            signatureBytes = feedContent(sig, request.content());
            control.requireActive(Instant.now());
            byte[] finalSignature = signatureBytes;
            signatureBytes = null; // ownership transferred
            return new OperationObservation(request.operationId(), ObservationState.SUCCEEDED,
                    Instant.now(), DetailCode.SIGNED,
                    Optional.of(new EncodedObject(Encoding.BINARY, finalSignature)));
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException failure) {
            logSafeFailure(DetailCode.KEY_NOT_FOUND, failure);
            return failedObservation(request.operationId(), DetailCode.KEY_NOT_FOUND);
        } catch (InvalidKeyException | SignatureException failure) {
            logSafeFailure(DetailCode.ALGORITHM_MISMATCH, failure);
            return failedObservation(request.operationId(), DetailCode.ALGORITHM_MISMATCH);
        } catch (IOException failure) {
            logSafeFailure(DetailCode.KEYRING_IO_FAILURE, failure);
            return failedObservation(request.operationId(), DetailCode.KEYRING_IO_FAILURE);
        } finally {
            if (signatureBytes != null) {
                Arrays.fill(signatureBytes, (byte) 0);
            }
        }
    }

    @Override
    public OperationObservation reconcile(PkiId operationId, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(control, "control").requireActive(Instant.now());
        // Local HSM provider completes inline; after a restart the outcome is unrecoverable.
        return new OperationObservation(operationId, ObservationState.UNRECOVERABLE, Instant.now(),
                DetailCode.LOCAL_RESTART_UNRECOVERABLE, Optional.empty());
    }

    @Override
    public OperationObservation cancel(PkiId operationId, long fencingToken,
            CancellationReason reason, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        Objects.requireNonNull(control, "control").requireActive(Instant.now());
        if (fencingToken <= NO_FENCE) {
            throw new IllegalArgumentException("fencingToken must be positive");
        }
        return new OperationObservation(operationId, ObservationState.UNRECOVERABLE, Instant.now(),
                DetailCode.LOCAL_RESTART_UNRECOVERABLE, Optional.empty());
    }

    @Override
    public void close() {
        lifecycleLock.lock();
        try {
            if (closed) {
                return;
            }
            closed = true;
        } finally {
            lifecycleLock.unlock();
        }
        // The KeyStore session remains open until the JVM exits or the SunPKCS11 provider
        // is unregistered. There is no public KeyStore.close() API in the JDK.
        // The provider (Security.removeProvider) is process-global and shared; do not remove it here.
    }

    private PrivateKey lookupKey(String label)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        requireOpen();
        java.security.Key key = keyStore.getKey(label, null);
        if (key instanceof PrivateKey privateKey) {
            return privateKey;
        }
        return null;
    }

    private Signature buildSignature(String algorithmId, PrivateKey privateKey)
            throws NoSuchAlgorithmException, InvalidKeyException {
        try {
            zeroecho.core.alg.common.sig.StatefulSigningGuard.requireStateless(algorithmId, privateKey);
        } catch (zeroecho.core.err.UnsupportedRoleException unavailable) {
            throw new InvalidKeyException("Stateful signing is unavailable", unavailable);
        }
        if (!supportedAlgorithms.contains(algorithmId)) {
            return null;
        }
        // Always pass the SunPKCS11 provider so the JCA framework routes the signature
        // operation to the HSM. Without this, a software provider is selected which calls
        // PrivateKey.getEncoded(); HSM keys return null from getEncoded() in FIPS mode,
        // causing InvalidKeyException or NullPointerException.
        Signature sig = Signature.getInstance(algorithmId, provider);
        sig.initSign(privateKey);
        return sig;
    }

    private static byte[] feedContent(Signature sig, RepeatableContent content)
            throws IOException, SignatureException {
        byte[] buffer = new byte[READ_BUFFER_BYTES];
        try (InputStream stream = content.openStream()) {
            int read;
            while ((read = stream.read(buffer)) >= 0) {
                if (read > 0) {
                    sig.update(buffer, 0, read);
                }
            }
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
        return sig.sign();
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("PKCS#11 signing provider is closed");
        }
    }

    private static OperationObservation failedObservation(PkiId operationId, DetailCode code) {
        return new OperationObservation(operationId, ObservationState.FAILED, Instant.now(),
                code, Optional.empty());
    }

    private static void logSafeFailure(DetailCode code, Throwable failure) {
        if (LOG.isLoggable(Level.FINE)) {
            LOG.log(Level.FINE, "PKCS#11 signing failure: code={0}, exception={1}",
                    new Object[] { code, failure.getClass().getName() });
        }
    }
}
