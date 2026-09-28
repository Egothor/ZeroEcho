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
package zeroecho.pki.testkit;

import java.security.KeyPair;
import java.security.Signature;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.math.BigInteger;
import java.util.LinkedHashMap;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DigestInfo;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.StandardDSAEncoding;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.spi.crypto.SigningInputCapabilities;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSigningState;
import zeroecho.pki.spi.crypto.remote.RemoteSigningTransport.RemoteSigningStatus;

/**
 * Test reference implementation of a remote signing service, exercised in process
 * as a {@link RemoteSigningTransport} and reusable behind an HTTP reference
 * server. It models an authoritative remote signer: per-instance idempotency
 * keyed by {@code submissionId}, optional external (human) approval before
 * signing, best-effort push callbacks, and fenced cancellation — while never
 * returning private key material. Deadline expiry is deliberately left to the
 * caller's orchestration, so this service reports only {@code QUEUED},
 * {@code SIGNED}, {@code DENIED}, and {@code CANCELLED}.
 */
public final class ReferenceRemoteSigner implements RemoteSigningTransport {

    private final Map<String, KeyPair> keys;
    private final boolean requireApproval;
    private final RemoteCapabilities capabilities;
    private final Map<String, RemoteSigningStatus> statuses = new HashMap<>();
    private final Map<String, String> fingerprints = new HashMap<>();
    private final Map<String, Long> fences = new HashMap<>();
    private final Map<String, RemoteSignRequest> pendingApproval = new HashMap<>();
    private final List<RemoteSigningCallback> callbacks = new CopyOnWriteArrayList<>();

    /**
     * Creates the reference signer.
     *
     * @param keys map of remote key handle to JCA key pair
     * @param requireApproval when {@code true}, submissions park in
     *                        {@link RemoteSigningState#QUEUED} until {@link #approve}
     */
    public ReferenceRemoteSigner(Map<String, KeyPair> keys, boolean requireApproval) {
        this(keys, requireApproval, defaultCapabilities());
    }

    /** Creates a signer with exact server-captured capabilities. */
    public ReferenceRemoteSigner(Map<String, KeyPair> keys, boolean requireApproval, RemoteCapabilities capabilities) {
        this.keys = new HashMap<>(Objects.requireNonNull(keys, "keys"));
        this.requireApproval = requireApproval;
        this.capabilities = Objects.requireNonNull(capabilities, "capabilities");
    }

    /** Returns the standard reference protocol capability fixture. */
    public static RemoteCapabilities defaultCapabilities() {
        byte[] configurationCommitment = new byte[32];
        for (int index = 0; index < configurationCommitment.length; index++) {
            configurationCommitment[index] = (byte) (0x40 + index);
        }
        Map<String, AlgorithmIdentity> prehash = new LinkedHashMap<>();
        for (AlgorithmIdentity identity : List.of(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                BootstrapAlgorithmIdentities.RSA_PKCS1_SHA384, BootstrapAlgorithmIdentities.RSA_PKCS1_SHA512,
                BootstrapAlgorithmIdentities.RSA_PSS_SHA256, BootstrapAlgorithmIdentities.ECDSA_SHA256,
                BootstrapAlgorithmIdentities.ECDSA_SHA384, BootstrapAlgorithmIdentities.ECDSA_SHA512)) {
            prehash.put(identity.canonicalForm(), SigningInputCapabilities.requiredDigest(identity));
        }
        java.util.Set<String> algorithms = new java.util.HashSet<>(prehash.keySet());
        algorithms.add(BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm());
        algorithms.add(BootstrapAlgorithmIdentities.ED448_SIGNATURE.canonicalForm());
        return new RemoteCapabilities(algorithms, configurationCommitment, SigningInputCapabilities.PROTOCOL_VERSION,
                new SigningInputCapabilities(SigningInputCapabilities.REMOTE_RAW_LIMIT, prehash));
    }

    @Override
    public synchronized RemoteSigningStatus submit(RemoteSignRequest request, RemoteCallControl control) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(control, "control");
        if (control.cancellation().isCancelled() || !Instant.now().isBefore(control.deadline())
                || request.deadline().filter(value -> !Instant.now().isBefore(value)).isPresent()) {
            throw new IllegalStateException("Remote signing deadline or cancellation reached");
        }
        request.validate(capabilities);
        String fingerprint = request.wireFingerprint();
        String operationId = request.submissionId();
        String existing = fingerprints.get(operationId);
        if (existing != null) {
            if (!existing.equals(fingerprint)) {
                throw new IllegalStateException("Remote signing request conflicts with a prior submission");
            }
            if (request.fencingToken() < fences.get(operationId)) {
                throw new IllegalStateException("Stale remote signing fencing token");
            }
            return statuses.get(operationId);
        }
        fingerprints.put(operationId, fingerprint);
        fences.put(operationId, request.fencingToken());
        if (requireApproval) {
            RemoteSigningStatus queued = new RemoteSigningStatus(operationId, RemoteSigningState.QUEUED,
                    Instant.now(), Optional.empty(), "");
            pendingApproval.put(operationId, request);
            return store(operationId, queued);
        }
        return sign(operationId, request);
    }

    @Override
    public synchronized RemoteSigningStatus status(String operationId, RemoteCallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        RemoteSigningStatus current = statuses.get(operationId);
        if (current == null) {
            return new RemoteSigningStatus(operationId, RemoteSigningState.DENIED, Instant.now(),
                    Optional.empty(), "");
        }
        return current;
    }

    @Override
    public synchronized RemoteSigningStatus cancel(String operationId, long fencingToken, String reason,
            RemoteCallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        RemoteSigningStatus current = statuses.get(operationId);
        if (current == null) {
            return new RemoteSigningStatus(operationId, RemoteSigningState.UNKNOWN, Instant.now(),
                    Optional.empty(), "");
        }
        long currentFence = fences.getOrDefault(operationId, 0L);
        if (current.state().isTerminal()) {
            return current;
        }
        if (fencingToken < currentFence) {
            return current;
        }
        fences.put(operationId, fencingToken);
        pendingApproval.remove(operationId);
        return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.CANCELLED, Instant.now(),
                Optional.empty(), ""));
    }

    @Override
    public synchronized byte[] publicKeyInfo(String keyHandle, RemoteCallControl control) {
        KeyPair keyPair = keys.get(Objects.requireNonNull(keyHandle, "keyHandle"));
        if (keyPair == null) {
            throw new IllegalArgumentException("Unknown remote key handle");
        }
        return keyPair.getPublic().getEncoded();
    }

    @Override
    public synchronized RemoteCapabilities capabilities() {
        return capabilities;
    }

    @Override
    public boolean supportsCallbacks() {
        return true;
    }

    @Override
    public AutoCloseable subscribe(RemoteSigningCallback callback) {
        Objects.requireNonNull(callback, "callback");
        callbacks.add(callback);
        return () -> callbacks.remove(callback);
    }

    /** Approves a pending operation, driving it to a terminal signature. */
    public synchronized RemoteSigningStatus approve(String operationId) {
        RemoteSignRequest request = pendingApproval.remove(operationId);
        if (request == null) {
            throw new IllegalStateException("No pending approval for operation");
        }
        return sign(operationId, request);
    }

    /** Denies a pending operation with a non-secret justification. */
    public synchronized RemoteSigningStatus deny(String operationId, String reason) {
        pendingApproval.remove(operationId);
        return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.DENIED, Instant.now(),
                Optional.empty(), ""));
    }

    @Override
    public void close() {
        callbacks.clear();
    }

    private RemoteSigningStatus sign(String operationId, RemoteSignRequest request) {
        KeyPair keyPair = keys.get(request.keyHandle());
        if (keyPair == null) {
            return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.DENIED, Instant.now(),
                    Optional.empty(), ""));
        }
        try {
            byte[] produced;
            if (request.inputMode() == SigningInputCapabilities.Mode.PREHASHED_DIGEST) {
                produced = signDigest(keyPair, AlgorithmIdentity.parse(request.algorithmId(), List.of()),
                        request.content());
            } else {
                Signature signature = Signature.getInstance(jcaName(request.algorithmId()));
                signature.initSign(keyPair.getPrivate());
                signature.update(request.content());
                produced = signature.sign();
            }
            return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.SIGNED, Instant.now(),
                    Optional.of(produced), "BINARY"));
        } catch (Exception failure) {
            return store(operationId, new RemoteSigningStatus(operationId, RemoteSigningState.DENIED, Instant.now(),
                    Optional.empty(), ""));
        }
    }

    private RemoteSigningStatus store(String operationId, RemoteSigningStatus status) {
        statuses.put(operationId, status);
        for (RemoteSigningCallback callback : callbacks) {
            try {
                callback.onStatus(status);
            } catch (RuntimeException ignored) {
                // Callbacks are best-effort.
            }
        }
        return status;
    }

    private static String jcaName(String algorithmId) {
        return BootstrapAlgorithmIdentities.compatibilityAliases().entrySet().stream()
                .filter(entry -> entry.getValue().canonicalForm().equals(algorithmId))
                .map(Map.Entry::getKey).findFirst().orElseThrow();
    }

    private static byte[] signDigest(KeyPair key, AlgorithmIdentity identity, byte[] digest) throws Exception {
        if (identity.parameters() instanceof AlgorithmIdentity.RsaPssParameters parameters) {
            PSSSigner signer = PSSSigner.createRawSigner(new RSABlindedEngine(), digest(parameters.hash()),
                    digest(parameters.maskHash()), parameters.saltLength(), PSSSigner.TRAILER_IMPLICIT);
            signer.init(true, new ParametersWithRandom(PrivateKeyFactory.createKey(key.getPrivate().getEncoded()),
                    new SecureRandom()));
            signer.update(digest, 0, digest.length);
            return signer.generateSignature();
        }
        if (identity.family().equals(BootstrapAlgorithmIdentities.ECDSA_SHA256.family())) {
            ECPrivateKeyParameters parameters = (ECPrivateKeyParameters) PrivateKeyFactory.createKey(
                    key.getPrivate().getEncoded());
            ECDSASigner signer = new ECDSASigner();
            signer.init(true, new ParametersWithRandom(parameters, new SecureRandom()));
            BigInteger[] signature = signer.generateSignature(digest);
            return StandardDSAEncoding.INSTANCE.encode(parameters.getParameters().getN(), signature[0], signature[1]);
        }
        AlgorithmIdentifier digestAlgorithm = new AlgorithmIdentifier(switch (digest.length) {
            case 32 -> NISTObjectIdentifiers.id_sha256;
            case 48 -> NISTObjectIdentifiers.id_sha384;
            case 64 -> NISTObjectIdentifiers.id_sha512;
            default -> throw new IllegalArgumentException("Unsupported digest");
        }, DERNull.INSTANCE);
        byte[] digestInfo = new DigestInfo(digestAlgorithm, digest).getEncoded("DER");
        PKCS1Encoding signer = new PKCS1Encoding(new RSABlindedEngine());
        signer.init(true, new ParametersWithRandom(PrivateKeyFactory.createKey(key.getPrivate().getEncoded()),
                new SecureRandom()));
        return signer.processBlock(digestInfo, 0, digestInfo.length);
    }

    private static Digest digest(AlgorithmIdentity identity) {
        return switch (SigningInputCapabilities.digestLength(identity)) {
            case 32 -> new SHA256Digest();
            case 48 -> new SHA384Digest();
            case 64 -> new SHA512Digest();
            default -> throw new IllegalArgumentException("Unsupported digest");
        };
    }
}
