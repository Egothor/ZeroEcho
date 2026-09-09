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

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import java.security.cert.X509Certificate;

import zeroecho.pkix.Pkix;

import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallengeIssuance;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofChallengeRequest;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofResult;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewPage;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.application.CredentialConfirmationProofRuntimePolicy;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.confirmation.KeyPossessionProofChallengeContext;
import zeroecho.pki.spi.confirmation.KeyPossessionProofCredential;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;
import zeroecho.pki.spi.confirmation.KeyPossessionProofPresentation;
import zeroecho.pki.spi.confirmation.KeyPossessionProofProvider;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;
import zeroecho.pki.spi.confirmation.KeyPossessionProofVerification;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Default store-backed confirmation facade with session lifecycle enforcement.
 *
 * <p>Proof issuance takes O(D + K) CPU time. Pending proof verification takes
 * O(D + T + R + V(K)) CPU time, where D is certificate DER length bounded to
 * 1 MiB, T is canonical proof-transcript length bounded to 2 KiB, R is response
 * length bounded by the exact suite descriptor, and V(K) is the provider's
 * algorithm-dependent verification cost for key K. Verification additionally
 * performs a constant count of O(log M) metadata point operations and one
 * best-effort audit I/O operation. Peak auxiliary memory is bounded but has
 * parser-dependent constants and object graphs; it includes the DER, canonical
 * re-encoding, parsed certificate, extracted key, temporary public-key
 * encodings, and bounded proof objects. Exact terminal replay performs only
 * bounded point-store work and does not invoke a proof provider.</p>
 */
public final class DefaultCredentialConfirmationService implements CredentialConfirmationService {

    private final PkiStore store;
    private final Runnable lifecycleGuard;
    private final Map<String, KeyPossessionProofProvider> proofProviders;
    private final Optional<CredentialConfirmationProofRuntimePolicy> proofPolicy;
    private final SecureRandom secureRandom;
    private final Clock clock;
    private final CredentialConfirmationAudit audit;

    /**
     * Creates a facade over one session-owned store.
     *
     * @param store authoritative store owned by the session
     * @param lifecycleGuard guard rejecting access outside the session lifecycle
     * @param proofProviders immutable suite-ID lookup composed before store use
     * @param proofPolicy optional immutable server-controlled challenge policy
     * @param secureRandom session-local cryptographically secure nonce source
     * @param auditSink optional session-owned best-effort audit sink
     * @param clock authoritative session clock used for proof liveness and audit timestamps
     */
    public DefaultCredentialConfirmationService(PkiStore store, Runnable lifecycleGuard,
            Map<String, KeyPossessionProofProvider> proofProviders,
            Optional<CredentialConfirmationProofRuntimePolicy> proofPolicy,
            SecureRandom secureRandom, Optional<AuditSink> auditSink, Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.lifecycleGuard = Objects.requireNonNull(lifecycleGuard, "lifecycleGuard");
        this.proofProviders = Map.copyOf(Objects.requireNonNull(proofProviders, "proofProviders"));
        this.proofPolicy = Objects.requireNonNull(proofPolicy, "proofPolicy");
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.audit = new CredentialConfirmationAudit(auditSink, this.clock);
    }

    @Override
    public CredentialConfirmationLifecycle initialize(
            CredentialConfirmationInitialization initialization) {
        lifecycleGuard.run();
        return store.initializeCredentialConfirmation(
                Objects.requireNonNull(initialization, "initialization"));
    }

    @Override
    public Optional<CredentialConfirmationLifecycle> get(PkiId credentialId) {
        lifecycleGuard.run();
        return store.getCredentialConfirmation(Objects.requireNonNull(credentialId, "credentialId"));
    }

    @Override
    public CredentialConfirmationProofChallenge issueProofChallenge(
            CredentialConfirmationProofChallengeRequest request) {
        lifecycleGuard.run();
        CredentialConfirmationProofChallengeRequest exact = Objects.requireNonNull(request, "request");
        CredentialConfirmationLifecycle lifecycle = requirePendingLifecycle(exact);
        Optional<CredentialConfirmationChallenge> existing =
                store.getCredentialConfirmationChallenge(exact.credentialId());
        ChallengeSettings settings = existing.map(challenge -> settings(challenge, lifecycle))
                .orElseGet(() -> settings(lifecycle));
        ProviderSelection selection = requireProvider(settings.proofSuiteBinding());
        KeyPossessionProofCredential credential = authoritativeCredential(
                exact.credentialId(), settings.proofSuiteBinding());
        selection.provider().validateCredential(credential);

        byte[] nonce = new byte[CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES];
        CredentialConfirmationChallenge committed;
        try {
            secureRandom.nextBytes(nonce);
            committed = store.issueCredentialConfirmationChallenge(
                    new CredentialConfirmationChallengeIssuance(settings.realm(), settings.serverAudience(),
                            exact.credentialId(), exact.expectedLifecycleRevision(),
                            exact.expectedLifecycleRecordCommitment(), settings.proofSuiteBinding(),
                            nonce, settings.timeToLive()));
        } finally {
            Arrays.fill(nonce, (byte) 0);
        }

        ChallengeSettings committedSettings = settings(committed, lifecycle);
        if (!settings.equals(committedSettings)) {
            throw new IllegalStateException("Committed proof challenge differs from its authoritative settings");
        }
        ProviderSelection committedSelection = requireProvider(committed.proofSuiteBinding());
        if (!selection.descriptor().equals(committedSelection.descriptor())) {
            throw new IllegalStateException("Credential confirmation proof provider descriptor changed");
        }
        KeyPossessionProofChallengeContext context = new KeyPossessionProofChallengeContext(
                committed.realm(), committed.serverAudience(), committed.credentialId(),
                committed.proofSuiteBinding(), committed.rawChallenge(), committed.expiresAt());
        requireCredentialContext(context, credential);
        KeyPossessionProofPresentation presentation = Objects.requireNonNull(
                committedSelection.provider().createChallenge(context), "proof challenge presentation");
        CredentialConfirmationProofCas proofCas = new CredentialConfirmationProofCas(
                committed.credentialId(), committed.expectedLifecycleRevision(),
                committed.expectedLifecycleRecordCommitment(), committed.recordCommitment());
        CredentialConfirmationProofChallenge result = new CredentialConfirmationProofChallenge(
                proofCas, committed.proofSuiteBinding(),
                committed.expiresAt(), committedSelection.descriptor().maximumResponseBytes(),
                presentation.canonicalBytes());
        audit.challengeAvailable(committed.credentialId());
        return result;
    }

    @Override
    public CredentialConfirmationProofResult verifyAndComplete(
            CredentialConfirmationProofSubmission submission) {
        lifecycleGuard.run();
        CredentialConfirmationProofSubmission exact = Objects.requireNonNull(submission, "submission");
        CredentialConfirmationProofCas proofCas = exact.proofCas();
        CredentialConfirmationLifecycle lifecycle = store.getCredentialConfirmation(proofCas.credentialId())
                .orElseThrow(() -> new IllegalStateException(
                        "Credential confirmation lifecycle is not initialized"));
        if (lifecycle.state() == CredentialConfirmationLifecycle.State.CONFIRMED) {
            store.completeCredentialConfirmation(proofCas);
            audit.submission(proofCas.credentialId(),
                    CredentialConfirmationProofResult.CONFIRMED.name());
            return CredentialConfirmationProofResult.CONFIRMED;
        }
        requirePendingProofLifecycle(lifecycle, proofCas);
        Optional<CredentialConfirmationChallenge> storedChallenge =
                store.getCredentialConfirmationChallenge(proofCas.credentialId());
        if (storedChallenge.isEmpty()) {
            CredentialConfirmationProofResult result = resolveMissingChallengeRace(proofCas);
            audit.submission(proofCas.credentialId(), result.name());
            return result;
        }
        CredentialConfirmationChallenge challenge = storedChallenge.orElseThrow();
        settings(challenge, lifecycle);
        if (!challenge.recordCommitment().equals(proofCas.expectedChallengeRecordCommitment())) {
            throw new IllegalArgumentException("Credential confirmation challenge CAS conflicts");
        }
        CredentialConfirmationProofLiveness.requireLive(challenge, clock);
        ProviderSelection selection = requireProvider(challenge.proofSuiteBinding());
        KeyPossessionProofResponse response = boundedResponse(exact, selection.descriptor());
        KeyPossessionProofChallengeContext context = new KeyPossessionProofChallengeContext(
                challenge.realm(), challenge.serverAudience(), challenge.credentialId(),
                challenge.proofSuiteBinding(), challenge.rawChallenge(), challenge.expiresAt());
        KeyPossessionProofCredential credential = authoritativeCredential(
                challenge.credentialId(), challenge.proofSuiteBinding());
        requireCredentialContext(context, credential);
        KeyPossessionProofVerification verification = Objects.requireNonNull(
                selection.provider().verify(context, credential, response),
                "proof verification result");
        CredentialConfirmationProofResult result = switch (verification) {
            case REJECTED -> CredentialConfirmationProofResult.REJECTED;
            case VERIFIED -> {
                store.completeCredentialConfirmation(proofCas);
                yield CredentialConfirmationProofResult.CONFIRMED;
            }
        };
        audit.submission(proofCas.credentialId(), result.name());
        return result;
    }

    @Override
    public CredentialConfirmationReviewPage pagePendingReviews(PkiId authorityId,
            Optional<String> profileId, Instant cutoffInclusive,
            Optional<CredentialConfirmationReviewCursor> afterExclusive, int limit) {
        lifecycleGuard.run();
        return store.pagePendingCredentialConfirmationReviews(
                Objects.requireNonNull(authorityId, "authorityId"),
                Objects.requireNonNull(profileId, "profileId"),
                Objects.requireNonNull(cutoffInclusive, "cutoffInclusive"),
                Objects.requireNonNull(afterExclusive, "afterExclusive"), limit);
    }

    /* default */ Optional<KeyPossessionProofProvider> proofProvider(String suiteId) {
        return Optional.ofNullable(proofProviders.get(Objects.requireNonNull(suiteId, "suiteId")));
    }

    private CredentialConfirmationLifecycle requirePendingLifecycle(
            CredentialConfirmationProofChallengeRequest request) {
        CredentialConfirmationLifecycle lifecycle = store.getCredentialConfirmation(request.credentialId())
                .orElseThrow(() -> new IllegalStateException(
                        "Credential confirmation lifecycle is not initialized"));
        if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
            throw new IllegalStateException("Credential confirmation lifecycle is not pending");
        }
        if (lifecycle.revision() != request.expectedLifecycleRevision()
                || !lifecycle.recordCommitment().equals(request.expectedLifecycleRecordCommitment())) {
            throw new IllegalArgumentException("Credential confirmation lifecycle expectation does not match");
        }
        return lifecycle;
    }

    private static void requirePendingProofLifecycle(CredentialConfirmationLifecycle lifecycle,
            CredentialConfirmationProofCas proofCas) {
        if (lifecycle.state() != CredentialConfirmationLifecycle.State.PENDING) {
            throw new IllegalStateException("Credential confirmation lifecycle is not pending");
        }
        if (!lifecycle.credentialId().equals(proofCas.credentialId())
                || lifecycle.revision() != proofCas.expectedLifecycleRevision()
                || !lifecycle.recordCommitment().equals(
                        proofCas.expectedLifecycleRecordCommitment())) {
            throw new IllegalArgumentException("Credential confirmation lifecycle expectation does not match");
        }
    }

    private CredentialConfirmationProofResult resolveMissingChallengeRace(
            CredentialConfirmationProofCas proofCas) {
        CredentialConfirmationLifecycle reread = store.getCredentialConfirmation(proofCas.credentialId())
                .orElseThrow(() -> new IllegalStateException(
                        "Credential confirmation lifecycle is not initialized"));
        if (reread.state() != CredentialConfirmationLifecycle.State.CONFIRMED) {
            throw new IllegalStateException("Credential confirmation challenge is not initialized");
        }
        store.completeCredentialConfirmation(proofCas);
        return CredentialConfirmationProofResult.CONFIRMED;
    }

    private static KeyPossessionProofResponse boundedResponse(
            CredentialConfirmationProofSubmission submission,
            KeyPossessionProofDescriptor descriptor) {
        byte[] response = submission.response();
        try {
            if (response.length > descriptor.maximumResponseBytes()) {
                throw new IllegalArgumentException(
                        "Proof submission response exceeds the exact suite bound");
            }
            return new KeyPossessionProofResponse(response);
        } finally {
            Arrays.fill(response, (byte) 0);
        }
    }

    private ChallengeSettings settings(CredentialConfirmationLifecycle lifecycle) {
        CredentialConfirmationProofRuntimePolicy policy = proofPolicy.orElseThrow(() ->
                new IllegalStateException("Credential confirmation proof runtime policy is not configured"));
        if (!policy.proofSuiteBinding().proofSuiteRef().equals(lifecycle.proofSuite())) {
            throw new IllegalStateException("Proof runtime policy does not match the authoritative lifecycle suite");
        }
        return new ChallengeSettings(policy.realm(), policy.audience().value(),
                policy.proofSuiteBinding(), policy.challengeTimeToLive());
    }

    private static ChallengeSettings settings(CredentialConfirmationChallenge challenge,
            CredentialConfirmationLifecycle lifecycle) {
        if (!challenge.credentialId().equals(lifecycle.credentialId())
                || challenge.expectedLifecycleRevision() != lifecycle.revision()
                || !challenge.expectedLifecycleRecordCommitment().equals(lifecycle.recordCommitment())
                || challenge.initialDisclosurePolicy() != lifecycle.initialPolicy()
                || !challenge.confirmationPolicyCommitment().equals(lifecycle.initialPolicyCommitment())
                || !challenge.proofSuiteBinding().proofSuiteRef().equals(lifecycle.proofSuite())) {
            throw new IllegalStateException("Persisted proof challenge does not match its authoritative lifecycle");
        }
        Duration timeToLive = Duration.between(challenge.issuedAt(), challenge.expiresAt());
        return new ChallengeSettings(challenge.realm(), challenge.serverAudience(),
                challenge.proofSuiteBinding(), timeToLive);
    }

    private ProviderSelection requireProvider(ConfirmationProofSuiteBinding binding) {
        KeyPossessionProofProvider provider = proofProvider(binding.proofSuiteRef().suiteId())
                .orElseThrow(() -> new IllegalStateException(
                        "Credential confirmation proof provider is not configured"));
        if (!binding.proofSuiteRef().suiteId().equals(provider.suiteId())) {
            throw new IllegalStateException("Credential confirmation proof provider identity does not match");
        }
        KeyPossessionProofDescriptor descriptor = Objects.requireNonNull(
                provider.descriptor(binding.rsaMaximumModulusBits()), "proof provider descriptor");
        if (!descriptor.proofSuiteBinding().equals(binding)
                || descriptor.challengeBytes() != CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES) {
            throw new IllegalStateException("Credential confirmation proof provider descriptor does not match");
        }
        return new ProviderSelection(provider, descriptor);
    }

    private KeyPossessionProofCredential authoritativeCredential(PkiId credentialId,
            ConfirmationProofSuiteBinding binding) {
        Credential credential = store.getCredential(credentialId)
                .orElseThrow(() -> new IllegalStateException("Credential is not available"));
        if (!credential.credentialId().equals(credentialId)
                || !BcX509CredentialFramework.FORMAT_ID.equals(credential.formatId())
                || credential.content().encoding() != Encoding.DER) {
            throw new IllegalStateException("Credential identity or encoding is inconsistent");
        }
        byte[] certificateDer = CredentialContent.materializeForBc(store, credential.content());
        try {
            String expectedId = "x509:" + HexFormat.of().formatHex(sha256(certificateDer));
            if (!credentialId.equals(new PkiId(expectedId))) {
                throw new IllegalStateException("Credential identity does not match authoritative certificate DER");
            }
            PublicKey publicKey = parseAuthoritativePublicKey(certificateDer);
            return new KeyPossessionProofCredential(binding, credentialId, publicKey);
        } finally {
            Arrays.fill(certificateDer, (byte) 0);
        }
    }

    private static PublicKey parseAuthoritativePublicKey(byte[] certificateDer) {
        byte[] canonical = null;
        byte[] subjectPublicKeyInfo = null;
        byte[] publicKeyEncoding = null;
        try {
            X509Certificate certificate = Pkix.parseCertificate(certificateDer);
            canonical = certificate.getEncoded();
            if (!MessageDigest.isEqual(certificateDer, canonical)) {
                throw new IllegalStateException("Authoritative X.509 credential is not canonical DER");
            }
            subjectPublicKeyInfo = Pkix.subjectPublicKeyInfo(certificate);
            PublicKey publicKey = Objects.requireNonNull(certificate.getPublicKey(),
                    "extracted credential public key");
            publicKeyEncoding = publicKey.getEncoded();
            if (publicKeyEncoding == null || publicKeyEncoding.length == 0
                    || !MessageDigest.isEqual(subjectPublicKeyInfo, publicKeyEncoding)) {
                throw new IllegalStateException("Authoritative X.509 public-key encoding is inconsistent");
            }
            return publicKey;
        } catch (GeneralSecurityException | IllegalArgumentException failure) {
            throw new IllegalStateException("Authoritative X.509 credential cannot be parsed safely", failure);
        } finally {
            if (canonical != null) {
                Arrays.fill(canonical, (byte) 0);
            }
            if (subjectPublicKeyInfo != null) {
                Arrays.fill(subjectPublicKeyInfo, (byte) 0);
            }
            if (publicKeyEncoding != null) {
                Arrays.fill(publicKeyEncoding, (byte) 0);
            }
        }
    }

    private static void requireCredentialContext(KeyPossessionProofChallengeContext context,
            KeyPossessionProofCredential credential) {
        if (!context.credentialId().equals(credential.credentialId())
                || !context.proofSuiteBinding().equals(credential.proofSuiteBinding())) {
            throw new IllegalStateException("Proof challenge context and authoritative credential differ");
        }
    }

    private static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private record ChallengeSettings(zeroecho.pki.api.confirmation.ConfirmationRealmBinding realm,
            String serverAudience, ConfirmationProofSuiteBinding proofSuiteBinding,
            Duration timeToLive) {
        private ChallengeSettings {
            Objects.requireNonNull(realm, "realm");
            Objects.requireNonNull(serverAudience, "serverAudience");
            Objects.requireNonNull(proofSuiteBinding, "proofSuiteBinding");
            Objects.requireNonNull(timeToLive, "timeToLive");
            if (timeToLive.getNano() != 0
                    || timeToLive.compareTo(CredentialConfirmationChallengeIssuance.MINIMUM_TIME_TO_LIVE) < 0
                    || timeToLive.compareTo(CredentialConfirmationChallengeIssuance.MAXIMUM_TIME_TO_LIVE) > 0) {
                throw new IllegalStateException("Persisted proof challenge lifetime is outside the supported range");
            }
        }
    }

    private record ProviderSelection(KeyPossessionProofProvider provider,
            KeyPossessionProofDescriptor descriptor) {
    }
}
