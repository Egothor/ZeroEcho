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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.bc.PkiBusContentSigner;
import zeroecho.pki.spi.audit.AuditSink;

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
    private static final int MAXIMUM_SPKI_BYTES = 1024 * 1024;
    private static final SecureRandom CHALLENGE_RANDOM = new SecureRandom();

    private final PublicKeyInfoResolver publicKeyResolver;
    private final PkiSigningBus signingBus;
    private final AuditSink auditSink;
    private final AlgorithmIdentity signatureIdentity;
    private final Optional<String> signatureBindingId;
    private final Duration signingTtl;

    /* default */ CaProofGate(PublicKeyInfoResolver publicKeyResolver, PkiSigningBus signingBus, AuditSink auditSink,
            String signatureAlgorithmId, Duration signingTtl) {
        this(publicKeyResolver, signingBus, auditSink,
                signingBus.authority().resolveIdentity(Objects.requireNonNull(signatureAlgorithmId,
                        "signatureAlgorithmId")), Optional.empty(), signingTtl);
    }

    /* default */ CaProofGate(PublicKeyInfoResolver publicKeyResolver, PkiSigningBus signingBus, AuditSink auditSink,
            AlgorithmIdentity signatureIdentity, Duration signingTtl) {
        this(publicKeyResolver, signingBus, auditSink, signatureIdentity, Optional.empty(), signingTtl);
    }

    /* default */ CaProofGate(PublicKeyInfoResolver publicKeyResolver, PkiSigningBus signingBus, AuditSink auditSink,
            AlgorithmIdentity signatureIdentity, Optional<String> signatureBindingId, Duration signingTtl) {
        this.publicKeyResolver = Objects.requireNonNull(publicKeyResolver, "publicKeyResolver");
        this.signingBus = Objects.requireNonNull(signingBus, "signingBus");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.signatureIdentity = Objects.requireNonNull(signatureIdentity, "signatureIdentity");
        this.signatureBindingId = Objects.requireNonNull(signatureBindingId, "signatureBindingId");
        this.signingTtl = Objects.requireNonNull(signingTtl, "signingTtl");
    }

    /* default */ PkiBusContentSigner signer(ManagedKeyProof proof) {
        return signatureBindingId.isPresent()
                ? new PkiBusContentSigner(signingBus, proof.keyRef(), signatureIdentity,
                        signatureBindingId.orElseThrow(), signingTtl)
                : new PkiBusContentSigner(signingBus, proof.keyRef(), signatureIdentity, signingTtl);
    }

    /* default */ PkiBusContentSigner signer(ManagedKeyProof proof,
            zeroecho.pki.api.profile.X509AlgorithmBindingPolicy bindingPolicy) {
        Optional<String> bindingId = bindingPolicy.certificateSignature()
                .map(zeroecho.pki.api.profile.X509AlgorithmBindingPolicy.BindingReference::bindingId);
        return bindingId.isPresent()
                ? new PkiBusContentSigner(signingBus, proof.keyRef(), signatureIdentity, bindingId.orElseThrow(),
                        signingTtl)
                : new PkiBusContentSigner(signingBus, proof.keyRef(), signatureIdentity, signingTtl);
    }

    /* default */ SubjectPublicKeyInfo parseRootSpki(EncodedObject spki, FormatId formatId) {
        if (spki.encoding() != Encoding.DER) {
            throw rejection("CREATE_ROOT_REJECTED", formatId, Optional.empty(), "ROOT_MANAGED_KEY_INVALID");
        }
        byte[] encoded = spki.bytes();
        try {
            return parseValidatedSpki(encoded);
        } catch (IOException | RuntimeException ex) { // NOPMD - malformed resolver output fails closed
            throw rejection("CREATE_ROOT_REJECTED", formatId, Optional.empty(), "ROOT_MANAGED_KEY_INVALID");
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /* default */ boolean rootProofIsValid(X509CertificateHolder certificate, EncodedObject expectedSpki) {
        if (expectedSpki.encoding() != Encoding.DER) {
            return false;
        }
        try {
            byte[] embeddedSpki = certificate.getSubjectPublicKeyInfo().getEncoded();
            BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(signingBus.authority().bindings());
            AlgorithmIdentity outer = adapter.decode(certificate.getSignatureAlgorithm(),
                    X509AlgorithmRole.SIGNATURE_ALGORITHM);
            AlgorithmIdentity inner = adapter.decode(
                    certificate.toASN1Structure().getTBSCertificate().getSignature(),
                    X509AlgorithmRole.SIGNATURE_ALGORITHM);
            AlgorithmIdentity key = adapter.decode(certificate.getSubjectPublicKeyInfo().getAlgorithm(),
                    X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            X509ExecutionPlan<BcX509VerificationExecutor> plan = signingBus.authority().plan(outer, key,
                    AlgorithmExecutionCapability.Direction.VERIFY,
                    Optional.of(BcX509VerificationExecutor.IMPLEMENTATION_ID), "root-proof",
                    BcX509VerificationExecutor.class);
            BcX509VerificationExecutor executor = plan.executor();
            boolean verified = executor.verify(signingBus.authority(), plan, certificate.getSubjectPublicKeyInfo(),
                    certificate.getSignatureAlgorithm(),
                    new ImmutableByteContent(certificate.toASN1Structure().getTBSCertificate().getEncoded()),
                    certificate.getSignature());
            return MessageDigest.isEqual(expectedSpki.bytes(), embeddedSpki) && verified && outer.equals(inner);
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
            Arrays.fill(exactSpki, (byte) 0);
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
        byte[] encoded = resolved.bytes();
        try {
            parseValidatedSpki(encoded);
            return new EncodedObject(Encoding.DER, encoded);
        } catch (IOException | RuntimeException exception) { // NOPMD - hostile resolver output is redacted
            throw rejection(auditAction, formatId, subjectCaId, "MANAGED_KEY_INVALID");
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
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
        try (PkiBusContentSigner contentSigner = new PkiBusContentSigner(signingBus, keyRef, signatureIdentity,
                signingTtl)) {
            contentSigner.getOutputStream().write(challenge);
            return contentSigner.getSignature();
        } catch (IOException ex) {
            throw new PkiException("Managed-key challenge buffering failed: code=CHALLENGE_BUFFER_FAILED");
        }
    }

    private boolean verifyChallenge(byte[] spkiDer, byte[] challenge, byte[] signature) {
        try {
            SubjectPublicKeyInfo spki = parseValidatedSpki(spkiDer);
            BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(signingBus.authority().bindings());
            AlgorithmIdentity keyIdentity = adapter.decode(spki.getAlgorithm(),
                    X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
            X509ExecutionPlan<BcX509VerificationExecutor> plan = signingBus.authority().plan(signatureIdentity,
                    keyIdentity, AlgorithmExecutionCapability.Direction.VERIFY,
                    Optional.of(BcX509VerificationExecutor.IMPLEMENTATION_ID), "managed-key-proof",
                    BcX509VerificationExecutor.class);
            BcX509VerificationExecutor executor = plan.executor();
            return executor.verify(signingBus.authority(), plan, spki,
                    adapter.encode(signatureIdentity, X509AlgorithmRole.SIGNATURE_ALGORITHM),
                    new ImmutableByteContent(challenge), signature);
        } catch (Exception ex) {
            return false;
        }
    }

    private SubjectPublicKeyInfo parseValidatedSpki(byte[] encoded) throws IOException {
        new StreamingDerReader().validateSubjectPublicKeyInfo(encoded, MAXIMUM_SPKI_BYTES);
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(encoded);
        new BcX509AlgorithmAdapter(signingBus.authority().bindings()).decode(spki.getAlgorithm(),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        return spki;
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

}
