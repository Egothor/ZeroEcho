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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.KeyUsage;
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
import zeroecho.core.io.TailStrippingInputStream;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spec.ContextSpec;
import zeroecho.core.storage.KeyringStore;
import zeroecho.sdk.ZeroEchoSession;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * ZeroEcho-lib backed implementation of {@link SignatureWorkflow}.
 *
 * <p>
 * This provider forms a cryptographic boundary between the PKI orchestration
 * layer and ZeroEcho-lib based key material handling backed by
 * {@link KeyringStore}. It resolves opaque {@link KeyRef} values to provider-
 * local keyring aliases, materializes the required key objects inside this
 * boundary, and performs signing or verification through
 * the explicit {@link ZeroEchoSession} and {@link SignatureContext}.
 * </p>
 *
 * <p>
 * The implementation is intentionally synchronous from its internal execution
 * perspective, but it still conforms to the {@link SignatureWorkflow} contract
 * by returning an operation identifier and exposing the terminal outcome
 * through {@link #status(PkiId)}. Each submitted operation is executed
 * immediately in the caller thread, and the resulting terminal status is stored
 * in an internal in-memory registry.
 * </p>
 *
 * <h2>Supported operations</h2>
 * <ul>
 * <li>{@link #submitSign(SignRequest)} resolves a private/public key pair from
 * the configured {@link KeyringStore}, validates the requested algorithm
 * compatibility, produces a signature over the supplied payload, and stores the
 * result as a terminal successful or failed operation status.</li>
 * <li>{@link #submitVerify(VerifyRequest)} verifies a signature either against
 * a key resolved from {@link VerifyRequest#publicKeyRef()} or against a caller-
 * supplied encoded public key from
 * {@link VerifyRequest#publicKeyEncoded()}.</li>
 * <li>{@link #status(PkiId)} returns the last known operation status from the
 * in-memory status registry, or a stable failed status for unknown operation
 * identifiers.</li>
 * <li>{@link #register(NotificationSink)} installs an in-memory notification
 * sink that is called whenever an operation status changes.</li>
 * </ul>
 *
 * <h2>Failure model</h2>
 * <p>
 * Validation failures, policy mismatches, lookup problems, and cryptographic
 * execution failures must not escape the public workflow boundary as uncaught
 * exceptions once an operation has been accepted for processing. Instead, the
 * provider always returns an operation identifier and records a terminal
 * {@link State#FAILED} status with a stable non-secret detail code retrievable
 * through {@link #status(PkiId)}.
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
 * <p>
 * The provider may derive the corresponding public alias from a signing key
 * reference in order to obtain public-key metadata needed for algorithm checks
 * and interop processing.
 * </p>
 *
 * <h2>Algorithm handling</h2>
 * <p>
 * Requested signature algorithm identifiers are matched against the stored key
 * algorithm using {@link SignatureInteropProfiles} where available and by a
 * legacy normalization fallback for historical identifiers such as
 * {@code *withRSA} and {@code *withECDSA}. For interoperable algorithms, the
 * provider transparently maps between external signature form and the internal
 * ZeroEcho representation expected by {@link SignatureContext}.
 * </p>
 *
 * <h2>Persistence and lifecycle</h2>
 * <ul>
 * <li>Operation statuses and notification registrations are stored only in
 * memory and are lost when the provider is closed or the process restarts.</li>
 * <li>The underlying {@link KeyringStore} is loaded lazily on first use and
 * then cached in the provider instance.</li>
 * <li>{@link #close()} clears in-memory operation state and discards the cached
 * keyring reference.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Never logs {@link KeyRef} values.</li>
 * <li>Never logs payload bytes or signature bytes.</li>
 * <li>Never returns private key material; private keys are materialized only
 * within this provider boundary.</li>
 * <li>Notification sinks must be treated as trusted local integration points,
 * because they receive operation identifiers and status metadata for all
 * operations observed by this provider instance.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * The internal status and sink registries are backed by synchronized maps. This
 * provides basic shared-state safety for the current implementation, but
 * callbacks are invoked inline from the status update path and may therefore
 * affect latency or local failure behavior of the calling thread. This class
 * should be treated as safe for ordinary concurrent access, not as a high-
 * throughput lock-free implementation.
 * </p>
 */
public final class ZeroEchoLibSignatureWorkflow implements SignatureWorkflow { // NOPMD

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

    private final String id;
    private final java.nio.file.Path keyringPath;
    private final String keyRefPrefix;
    private final boolean requireComponentSuffix;
    private final ZeroEchoSession session;

    private final Map<PkiId, OperationStatus> statuses;
    private final Map<PkiId, NotificationSink> sinks;

    private volatile KeyringStore keyringOrNull; // NOPMD

    /* default */ ZeroEchoLibSignatureWorkflow(String id, java.nio.file.Path keyringPath, String keyRefPrefix,
            boolean requireComponentSuffix) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("id must not be blank");
        }
        if (keyringPath == null) {
            throw new IllegalArgumentException("keyringPath must not be null");
        }
        if (keyRefPrefix == null) {
            throw new IllegalArgumentException("keyRefPrefix must not be null");
        }
        this.id = id;
        this.keyringPath = keyringPath;
        this.keyRefPrefix = keyRefPrefix;
        this.requireComponentSuffix = requireComponentSuffix;
        this.session = new ZeroEchoSession();

        this.statuses = Collections.synchronizedMap(new HashMap<>());
        this.sinks = Collections.synchronizedMap(new HashMap<>());
    }

    @Override
    public String id() {
        return this.id;
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
     * The method validates the key reference, loads the corresponding private and
     * public key entries from the configured {@link KeyringStore}, verifies that
     * the requested signature algorithm is compatible with the stored key
     * algorithm, performs streaming signature generation, encodes the resulting
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
    public PkiId submitSign(SignRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        PkiId opId = newOperationId();
        putStatus(opId, new OperationStatus(State.RUNNING, Instant.now(), Optional.of(DC_SUBMITTED), Optional.empty()));

        try {
            KeyRefParts parts = parseKeyRefOrThrow(request.keyRef(), true);

            if (request.algorithmId() == null || request.algorithmId().isBlank()) {
                throw new InvalidRequestException(DC_INVALID_ALGORITHM_ID);
            }

            KeyringStore ks = requireKeyringOrThrow();

            KeyringStore.PrivateWithId prv;
            KeyringStore.PublicWithId pub;
            try {
                prv = ks.getPrivateWithId(parts.privateAlias);
                pub = ks.getPublicWithId(parts.publicAlias);
            } catch (GeneralSecurityException missing) {
                throw new InvalidRequestException(DC_KEY_NOT_FOUND, missing);
            }

            enforceAlgorithmMatchOrThrow(request.algorithmId(), prv.algorithm());

            byte[] signatureBytes = signStreaming(request.algorithmId(), prv.key(), pub.key(),
                    request.payload().bytes());

            Encoding outEnc = request.preferredSignatureEncoding().orElse(Encoding.BINARY);
            EncodedObject signature = encodeSignatureOrThrow(outEnc, signatureBytes);

            OperationResult result = new OperationResult(Optional.of(signature), Optional.empty());
            putStatus(opId,
                    new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of(DC_SIGNED), Optional.of(result)));
            return opId;

        } catch (InvalidRequestException inv) { // NOPMD
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(inv.detailCode), Optional.empty()));
            return opId;

        } catch (IOException io) {
            putStatus(opId, new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_KEYRING_IO_ERROR),
                    Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Sign failed due to IO (details suppressed)", io);
            }
            return opId;

        } catch (GeneralSecurityException sec) {
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Sign failed due to security exception (details suppressed)", sec);
            }
            return opId;

        } catch (RuntimeException ex) { // NOPMD
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Sign failed due to runtime exception (details suppressed)", ex);
            }
            return opId;
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
    public PkiId submitVerify(VerifyRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        PkiId opId = newOperationId();
        putStatus(opId, new OperationStatus(State.RUNNING, Instant.now(), Optional.of(DC_SUBMITTED), Optional.empty()));

        try {
            if (request.algorithmId() == null || request.algorithmId().isBlank()) {
                throw new InvalidRequestException(DC_INVALID_ALGORITHM_ID);
            }

            PublicKey pub = resolvePublicKeyOrThrow(request);

            byte[] sigBytes = decodeSignatureOrThrow(request.signature());
            boolean ok = verifyStreaming(request.algorithmId(), pub, request.payload().bytes(), sigBytes);

            OperationResult result = new OperationResult(Optional.empty(), Optional.of(ok));
            String dc = ok ? DC_VERIFIED : DC_REJECTED;
            putStatus(opId, new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of(dc), Optional.of(result)));
            return opId;

        } catch (InvalidRequestException inv) { // NOPMD
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(inv.detailCode), Optional.empty()));
            return opId;

        } catch (IOException io) {
            putStatus(opId, new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_KEYRING_IO_ERROR),
                    Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Verify failed due to IO (details suppressed)", io);
            }
            return opId;

        } catch (GeneralSecurityException sec) {
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Verify failed due to security exception (details suppressed)", sec);
            }
            return opId;

        } catch (RuntimeException ex) { // NOPMD
            putStatus(opId,
                    new OperationStatus(State.FAILED, Instant.now(), Optional.of(DC_CRYPTO_FAILURE), Optional.empty()));
            if (LOG.isLoggable(Level.FINE)) {
                LOG.log(Level.FINE, "Verify failed due to runtime exception (details suppressed)", ex);
            }
            return opId;
        }
    }

    /**
     * Returns the current status of a previously submitted operation.
     *
     * <p>
     * Because this implementation executes operations eagerly, returned statuses
     * are typically already terminal by the time callers first query them. Unknown
     * operation identifiers are mapped to a stable synthetic failed status with
     * detail code {@link #DC_UNKNOWN_OPERATION}.
     * </p>
     *
     * @param operationId workflow operation identifier; must not be {@code null}
     * @return current operation status, never {@code null}
     * @throws IllegalArgumentException if {@code operationId} is {@code null}
     */
    @Override
    public OperationStatus status(PkiId operationId) {
        if (operationId == null) {
            throw new IllegalArgumentException("operationId must not be null");
        }
        OperationStatus st = this.statuses.get(operationId);
        if (st == null) {
            return UNKNOWN_OPERATION_STATUS;
        }
        return st;
    }

    /**
     * Attempts to cancel a non-terminal operation.
     *
     * <p>
     * In the current implementation operations are executed eagerly and usually
     * reach a terminal state before cancellation is attempted. Cancellation
     * therefore succeeds only when a matching non-terminal status is still present
     * in the in-memory registry.
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
    public boolean cancel(PkiId operationId, String reason) {
        if (operationId == null) {
            throw new IllegalArgumentException("operationId must not be null");
        }
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        OperationStatus st = this.statuses.get(operationId);
        if (st == null || st.isTerminal()) {
            return false;
        }
        putStatus(operationId,
                new OperationStatus(State.CANCELLED, Instant.now(), Optional.of(DC_CANCELLED), Optional.empty()));
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
     * Clears in-memory workflow state and releases the cached keyring reference.
     *
     * <p>
     * This method does not delete the underlying keyring file and does not attempt
     * to persist or flush in-memory operation status.
     * </p>
     */
    @Override
    public void close() {
        this.statuses.clear();
        this.sinks.clear();
        this.keyringOrNull = null;
    }

    private KeyringStore requireKeyringOrThrow() throws IOException {
        KeyringStore ks = this.keyringOrNull;
        if (ks != null) {
            return ks;
        }
        KeyringStore loaded = KeyringStore.load(this.session, this.keyringPath);
        this.keyringOrNull = loaded;
        return loaded;
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
            String base = hasPrv ? v.substring(0, v.length() - 4) : v;
            String publicAlias = base + ".pub";
            return new KeyRefParts(privateAlias, publicAlias);
        }

        String publicAlias = hasPub ? v : (v + ".pub");
        return new KeyRefParts(publicAlias, publicAlias);
    }

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
            AlgorithmKeySpec spec = createPublicKeySpecOrThrow(request.algorithmId(), spki);
            String keyAlg = keyAlgorithmId(request.algorithmId());
            try {
                return importPublic(keyAlg, spec);
            } catch (GeneralSecurityException ex) {
                throw new InvalidRequestException(DC_CRYPTO_FAILURE, ex);
            }
        }

        throw new InvalidRequestException(DC_UNSUPPORTED_PUBLICKEY_FORM);
    }

    private <S extends AlgorithmKeySpec> PublicKey importPublic(String algorithmId, S spec)
            throws GeneralSecurityException {
        @SuppressWarnings("unchecked")
        Class<S> specType = (Class<S>) spec.getClass();
        return session.keyBuilders().asymmetric().publicImporter(algorithmId, specType).importPublic(spec);
    }

    private static byte[] decodePublicKeyOrThrow(EncodedObject publicKey) throws InvalidRequestException {
        if (publicKey.encoding() == Encoding.DER || publicKey.encoding() == Encoding.BINARY) {
            return publicKey.bytes().clone();
        }
        if (publicKey.encoding() == Encoding.PEM) {
            String text = new String(publicKey.bytes(), java.nio.charset.StandardCharsets.US_ASCII);
            return pemUnwrap(text);
        }
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

    private byte[] signStreaming(String algorithmId, PrivateKey prv, PublicKey pub, byte[] msg)
            throws GeneralSecurityException, IOException {

        Optional<SignatureInteropProfile> profile = SignatureInteropProfiles.resolve(algorithmId);
        String contextAlgorithmId = profile.map(SignatureInteropProfile::contextAlgorithmId).orElse(algorithmId);
        ContextSpec contextSpec = profile.map(SignatureInteropProfile::contextSpec).orElse(null);

        int sigLen;
        try (SignatureContext verifier = session.createContext(contextAlgorithmId, KeyUsage.VERIFY, pub,
                contextSpec)) {
            sigLen = verifier.tagLength();
        }

        try (SignatureContext signer = session.createContext(contextAlgorithmId, KeyUsage.SIGN, prv, contextSpec)) {
            final byte[][] sigHolder = new byte[1][];
            try (InputStream in = new TailStrippingInputStream(signer.wrap(new ByteArrayInputStream(msg)), sigLen,
                    8192) {
                @Override
                protected void processTail(byte[] tail) throws IOException {
                    sigHolder[0] = (tail == null) ? null : tail.clone();
                }
            }) {
                in.transferTo(OutputStream.nullOutputStream());
            }

            byte[] sig = sigHolder[0];
            if (sig == null || sig.length == 0) {
                throw new GeneralSecurityException("Signature trailer missing.");
            }
            if (profile.isPresent()) {
                return profile.get().internalToExternalSignature(sig);
            }
            return sig;
        }
    }

    private boolean verifyStreaming(String algorithmId, PublicKey pub, byte[] msg, byte[] signature)
            throws GeneralSecurityException, IOException {

        Optional<SignatureInteropProfile> profile = SignatureInteropProfiles.resolve(algorithmId);
        String contextAlgorithmId = profile.map(SignatureInteropProfile::contextAlgorithmId).orElse(algorithmId);
        ContextSpec contextSpec = profile.map(SignatureInteropProfile::contextSpec).orElse(null);
        byte[] internalSignature = signature;
        if (profile.isPresent()) {
            internalSignature = profile.get().externalToInternalSignature(signature);
        }

        try (SignatureContext verifier = session.createContext(contextAlgorithmId, KeyUsage.VERIFY, pub,
                contextSpec)) {
            verifier.setExpectedTag(internalSignature);
            try (InputStream in = verifier.wrap(new ByteArrayInputStream(msg))) {
                in.transferTo(OutputStream.nullOutputStream());
            }
            return true;
        } catch (Exception mismatch) {
            return false;
        }
    }

    private static EncodedObject encodeSignatureOrThrow(Encoding encoding, byte[] sigBytes)
            throws InvalidRequestException {
        if (encoding == Encoding.BINARY || encoding == Encoding.DER) {
            return new EncodedObject(encoding, sigBytes);
        }
        if (encoding == Encoding.PEM) {
            String pem = pemWrap("ZEROECHO SIGNATURE", sigBytes);
            return new EncodedObject(Encoding.PEM, pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        }
        throw new InvalidRequestException(DC_UNSUPPORTED_SIGNATURE_ENCODING);
    }

    private static byte[] decodeSignatureOrThrow(EncodedObject signature) throws InvalidRequestException {
        if (signature.encoding() == Encoding.BINARY || signature.encoding() == Encoding.DER) {
            return signature.bytes().clone();
        }
        if (signature.encoding() == Encoding.PEM) {
            String text = new String(signature.bytes(), java.nio.charset.StandardCharsets.US_ASCII);
            return pemUnwrap(text);
        }
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
        for (NotificationSink sink : this.sinks.values()) {
            try {
                sink.onStatusChanged(id, st);
            } catch (Throwable ignore) { // NOPMD
                // sink must not break provider
                LOG.log(Level.FINE, "cannot put status, ignoring", ignore);
            }
        }
    }

    private static PkiId newOperationId() {
        return new PkiId(UUID.randomUUID().toString());
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
     * For signing requests, {@link #privateAlias} is expected to address the
     * private component (e.g. {@code *.prv}) and {@link #publicAlias} the
     * corresponding public component (e.g. {@code *.pub}). For verification,
     * {@link #privateAlias} is unused and {@link #publicAlias} addresses the public
     * component.
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
