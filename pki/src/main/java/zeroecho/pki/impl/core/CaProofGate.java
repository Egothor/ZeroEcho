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
package zeroecho.pki.impl.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.util.async.AsyncState;
import zeroecho.pki.util.async.AsyncStatus;

/**
 * Internal fail-closed proof gate for CA signing keys.
 */
// PMD cannot infer that retaining boundary causes would violate the redaction contract.
@SuppressWarnings("PMD.PreserveStackTrace")
final class CaProofGate {

    private static final Principal SYSTEM_PKI = new Principal("SYSTEM", "pki");
    private static final Purpose CA_ISSUANCE_PURPOSE = new Purpose("CA_ISSUANCE");
    private static final byte[] MANAGED_KEY_CHALLENGE_DOMAIN = "ZeroEcho/PKI/managed-key-possession/v1\0"
            .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int CHALLENGE_NONCE_BYTES = 32;
    private static final SecureRandom CHALLENGE_RANDOM = new SecureRandom();

    private final PublicKeyInfoResolver publicKeyResolver;
    private final PkiSigningBus signingBus;
    private final AuditSink auditSink;
    private final String signatureAlgorithmId;
    private final Duration signingTtl;

    /* default */ CaProofGate(PublicKeyInfoResolver publicKeyResolver, PkiSigningBus signingBus, AuditSink auditSink,
            String signatureAlgorithmId, Duration signingTtl) {
        this.publicKeyResolver = Objects.requireNonNull(publicKeyResolver, "publicKeyResolver");
        this.signingBus = Objects.requireNonNull(signingBus, "signingBus");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.signatureAlgorithmId = Objects.requireNonNull(signatureAlgorithmId, "signatureAlgorithmId");
        this.signingTtl = Objects.requireNonNull(signingTtl, "signingTtl");
    }

    /* default */ ContentSigner signer(ManagedKeyProof proof) {
        return new BusBackedContentSigner(signingBus, proof.keyRef(), signatureAlgorithmId, signingTtl);
    }

    /* default */ SubjectPublicKeyInfo parseRootSpki(EncodedObject spki, FormatId formatId) {
        try {
            return SubjectPublicKeyInfo.getInstance(spki.bytes());
        } catch (RuntimeException ex) { // NOPMD - malformed resolver output fails closed
            throw rejection("CREATE_ROOT_REJECTED", formatId, Optional.empty(), "ROOT_MANAGED_KEY_INVALID");
        }
    }

    /* default */ boolean rootProofIsValid(X509CertificateHolder certificate, EncodedObject expectedSpki) {
        if (expectedSpki.encoding() != Encoding.DER) {
            return false;
        }
        try {
            byte[] embeddedSpki = certificate.getSubjectPublicKeyInfo().getEncoded();
            return MessageDigest.isEqual(expectedSpki.bytes(), embeddedSpki) && certificate.isSignatureValid(
                    new JcaContentVerifierProviderBuilder().build(certificate.getSubjectPublicKeyInfo()));
        } catch (Exception ex) {
            return false;
        }
    }

    /* default */ ManagedKeyProof proveManagedKey(KeyRef keyRef, FormatId formatId, String auditAction,
            Optional<PkiId> subjectCaId) {
        EncodedObject resolved = resolveManagedKey(keyRef, formatId, auditAction, subjectCaId);
        byte[] exactSpki = resolved.bytes().clone();
        byte[] challenge = new byte[MANAGED_KEY_CHALLENGE_DOMAIN.length + CHALLENGE_NONCE_BYTES];
        CHALLENGE_RANDOM.nextBytes(challenge);
        System.arraycopy(MANAGED_KEY_CHALLENGE_DOMAIN, 0, challenge, 0, MANAGED_KEY_CHALLENGE_DOMAIN.length);
        byte[] signature = null;
        try {
            try {
                signature = signManagedKeyChallenge(keyRef, challenge);
            } catch (RuntimeException ex) { // NOPMD - signing boundary failures reject with a stable code
                throw rejection(auditAction, formatId, subjectCaId, "MANAGED_KEY_PROOF_FAILED");
            }
            if (!verifyChallenge(exactSpki, challenge, signature)) {
                throw rejection(auditAction, formatId, subjectCaId, "MANAGED_KEY_PROOF_FAILED");
            }
            return new ManagedKeyProof(keyRef, formatId, new EncodedObject(Encoding.DER, exactSpki.clone()));
        } finally {
            Arrays.fill(challenge, (byte) 0);
            if (signature != null) {
                Arrays.fill(signature, (byte) 0);
            }
        }
    }

    /* default */ EncodedObject resolveManagedKey(KeyRef keyRef, FormatId formatId, String auditAction,
            Optional<PkiId> subjectCaId) {
        EncodedObject resolved;
        try {
            resolved = publicKeyResolver.resolveSpkiDer(keyRef);
        } catch (RuntimeException ex) { // NOPMD - managed-key resolution boundary fails closed
            throw rejection(auditAction, formatId, subjectCaId, "MANAGED_KEY_UNAVAILABLE");
        }
        if (resolved == null || resolved.encoding() != Encoding.DER) {
            throw rejection(auditAction, formatId, subjectCaId, "MANAGED_KEY_INVALID");
        }
        return new EncodedObject(Encoding.DER, resolved.bytes());
    }

    /* default */ PkiException rejection(String action, FormatId formatId, Optional<PkiId> objectId, String code) {
        PkiException rejection = new PkiException("CA proof rejected: " + code);
        try {
            auditSink.record(new AuditEvent(Instant.now(), "CA", action, SYSTEM_PKI, CA_ISSUANCE_PURPOSE, objectId,
                    Optional.of(formatId), Map.of("code", code)));
        } catch (RuntimeException auditFailure) { // NOPMD - preserve the stable domain rejection
            // Best-effort auditing must not expose listener-controlled diagnostics.
        }
        return rejection;
    }

    private byte[] signManagedKeyChallenge(KeyRef keyRef, byte[] challenge) {
        ContentSigner contentSigner = new BusBackedContentSigner(signingBus, keyRef, signatureAlgorithmId, signingTtl);
        try {
            contentSigner.getOutputStream().write(challenge);
        } catch (IOException ex) {
            throw new PkiException("Managed-key challenge buffering failed: code=CHALLENGE_BUFFER_FAILED");
        }
        return contentSigner.getSignature();
    }

    private boolean verifyChallenge(byte[] spkiDer, byte[] challenge, byte[] signature) {
        try {
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(spkiDer);
            ContentVerifier verifier = new JcaContentVerifierProviderBuilder().build(spki)
                    .get(new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithmId));
            verifier.getOutputStream().write(challenge);
            return verifier.verify(signature);
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Unforgeable package-local result of a completed managed-key challenge.
     */
    static final class ManagedKeyProof {

        private final KeyRef keyRef;
        private final FormatId formatId;
        private final EncodedObject exactPublicKey;

        private ManagedKeyProof(KeyRef keyRef, FormatId formatId, EncodedObject exactPublicKey) {
            this.keyRef = Objects.requireNonNull(keyRef, "keyRef");
            this.formatId = Objects.requireNonNull(formatId, "formatId");
            EncodedObject publicKey = Objects.requireNonNull(exactPublicKey, "exactPublicKey");
            this.exactPublicKey = new EncodedObject(publicKey.encoding(), publicKey.bytes());
        }

        /* default */ KeyRef keyRef() {
            return keyRef;
        }

        /* default */ FormatId formatId() {
            return formatId;
        }

        /* default */ EncodedObject exactPublicKey() {
            return new EncodedObject(exactPublicKey.encoding(), exactPublicKey.bytes());
        }
    }

    /**
     * Bounded synchronous adapter over the existing asynchronous signing bus.
     */
    private static final class BusBackedContentSigner implements ContentSigner {

        private final PkiSigningBus bus;
        private final KeyRef keyRef;
        private final String algorithmId;
        private final Duration ttl;
        private final ByteArrayOutputStream output;

        private BusBackedContentSigner(PkiSigningBus bus, KeyRef keyRef, String algorithmId, Duration ttl) {
            this.bus = bus;
            this.keyRef = keyRef;
            this.algorithmId = algorithmId;
            this.ttl = ttl;
            this.output = new ByteArrayOutputStream();
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new DefaultSignatureAlgorithmIdentifierFinder().find(algorithmId);
        }

        @Override
        public OutputStream getOutputStream() {
            return output;
        }

        @Override
        public byte[] getSignature() {
            byte[] tbs = output.toByteArray();
            try {
                Principal owner = new Principal("SYSTEM", "pki");
                PkiId opId = bus.newSubmissionId();
                EncodedObject payload = new EncodedObject(Encoding.BINARY, tbs);
                AccessContext accessContext = new AccessContext(owner, new Purpose("X509_SIGN"), Optional.empty(),
                        Optional.empty());
                PkiSigningBus.SignContinuation continuation = new PkiSigningBus.SignContinuation(accessContext,
                        algorithmId, payload, keyRef, Encoding.BINARY, Optional.empty());
                try {
                    bus.submitSign(opId, owner, keyRef, algorithmId, payload, ttl, Optional.of(continuation.encode()));
                } catch (RuntimeException failure) { // NOPMD - delete state if submission partially persisted it
                    deletePreservingFailure(opId);
                    throw failure;
                }
                return awaitSignature(opId);
            } finally {
                Arrays.fill(tbs, (byte) 0);
            }
        }

        @SuppressWarnings("PMD.AvoidCatchingGenericException")
        private byte[] awaitSignature(PkiId opId) {
            byte[] signature;
            try {
                signature = awaitSignatureBeforeCleanup(opId);
            } catch (RuntimeException failure) {
                deletePreservingFailure(opId);
                throw failure;
            }
            bus.retireSignOperation(opId, "completed");
            return signature;
        }

        private byte[] awaitSignatureBeforeCleanup(PkiId opId) {
            Instant deadline = Instant.now().plus(ttl);
            while (Instant.now().isBefore(deadline)) {
                bus.sweep(Instant.now());
                Optional<AsyncStatus> status = bus.status(opId);
                if (status.isPresent() && status.get().state() == AsyncState.SUCCEEDED) {
                    Optional<EncodedObject> result = bus.consumeResult(opId);
                    if (result.isEmpty()) {
                        throw new PkiException("Missing signature result");
                    }
                    return result.get().bytes();
                }
                if (status.isPresent() && isTerminalFailure(status.get().state())) {
                    throw new PkiException("Signing failed: " + status.get().state());
                }
                boundedWait(deadline);
            }
            throw new PkiException("Signing did not complete before TTL");
        }

        private static boolean isTerminalFailure(AsyncState state) {
            return state == AsyncState.FAILED || state == AsyncState.CANCELLED || state == AsyncState.EXPIRED;
        }

        @SuppressWarnings("PMD.DoNotUseThreads")
        private static void boundedWait(Instant deadline) {
            long remainingMillis = Duration.between(Instant.now(), deadline).toMillis();
            long waitMillis = Math.min(10L, Math.max(1L, remainingMillis));
            try {
                Thread.sleep(waitMillis);
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                throw new PkiException("Interrupted while awaiting signing", ex);
            }
        }

        private void deletePreservingFailure(PkiId opId) {
            try {
                bus.retireSignOperation(opId, "failed-or-expired");
            } catch (RuntimeException cleanupFailure) { // NOPMD - preserve primary failure
                // The primary safe failure remains authoritative; provider diagnostics are
                // discarded.
            }
        }

    }
}
