/* *****************************************************************************
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
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.alg.common.sig.SignatureInteropProfiles;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofChallenge;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509VerificationExecutor;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProvider.ContentCommitment;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.Pkix;

/**
 * Internal managed-key proof preparation owned by the session semantic service.
 * Uses the exact already-opened provider's public-key source and authorized SIGN
 * plan, without dispatch, reconcile, cancellation calls to the provider, acceptance
 * or artifact publication. Successful return transfers custody of one unowned
 * staged candidate to the caller; any subsequent failed adoption must retire it.
 * The caller supplies a fresh internal submission ID and configured TTL. Fairness
 * authority is {@link ManagedKeyProofCommand#authorityId(ManagedKeyProofRequest)}.
 * Work and auxiliary memory are O(bounded command plus SPKI bytes), apart from
 * provider lookup and durable staging. This preparer does not own its dependencies.
 */
public final class ManagedKeyProofPreparation {
    private final PkiStore store;
    private final SigningProvider provider;
    private final X509AuthoritySnapshot signingAuthority;
    private final X509AuthoritySnapshot verificationAuthority;
    private final BcX509VerificationExecutor verifier;
    private final AlgorithmIdentity signature;
    private final SecureRandom random;
    private final long pureEdDsaMaximum;

    /**
     * Binds preparation to exact process-local providers and algorithm authorities.
     * @param store owning staged-content and signing metadata store
     * @param provider already-opened selected signing provider; no fallback is used
     * @param signingAuthority SIGN authority bound to that exact provider
     * @param verificationAuthority installed VERIFY authority and bindings
     * @param verifier exact executor bound to the verification authority
     * @param signatureAlgorithm configured canonical signature identity
     * @param random secure random source for a fresh 32-byte challenge nonce
     * @param pureEdDsaMaximum inclusive raw pure-EdDSA message limit in bytes
     * @throws IllegalArgumentException if algorithm or bounds are invalid
     * @throws NullPointerException if store, provider, signingAuthority, verificationAuthority, verifier, random, signatureAlgorithm is null
     */
    public ManagedKeyProofPreparation(PkiStore store, SigningProvider provider,
            X509AuthoritySnapshot signingAuthority, X509AuthoritySnapshot verificationAuthority,
            BcX509VerificationExecutor verifier, String signatureAlgorithm, SecureRandom random,
            long pureEdDsaMaximum) {
        this.store = Objects.requireNonNull(store, "store");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.signingAuthority = Objects.requireNonNull(signingAuthority, "signingAuthority");
        this.verificationAuthority = Objects.requireNonNull(verificationAuthority, "verificationAuthority");
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.random = Objects.requireNonNull(random, "random");
        this.signature = signingAuthority.resolveIdentity(Objects.requireNonNull(signatureAlgorithm, "signatureAlgorithm"));
        if (signature.kind() != AlgorithmIdentity.Kind.SIGNATURE || !signature.canonicalForm().equals(signatureAlgorithm)
                || !signature.equals(verificationAuthority.resolveIdentity(signatureAlgorithm))) {
            throw new IllegalArgumentException("Managed key proof requires the exact configured signature identity");
        }
        X509SecurityFloor.requirePermitted(signature);
        if (pureEdDsaMaximum <= 0 || pureEdDsaMaximum > Integer.MAX_VALUE - 8L) {
            throw new IllegalArgumentException("Managed key proof pure EdDSA maximum is outside its finite bound");
        }
        this.pureEdDsaMaximum = pureEdDsaMaximum;
    }

    /**
     * Validates exact preparation metadata before a single bounded staging write.
     * No business-policy lookup or signing admission is performed by this internal
     * primitive. The caller must pass the frozen request through semantic adoption.
     * @param access trusted invocation context
     * @param request exact proof coordinates
     * @param submission internally allocated fresh submission ID
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-adoption cancellation
     * @return frozen request and its caller-owned staged candidate
     * @throws IOException if public-key DER, staging or cancellation fails
     * @throws RuntimeException if access, request, submission, ttl or cancellation is null;
     *         ttl is nonpositive or produces an unrepresentable deadline; submission
     *         is noncanonical or violates namespace, horizon or permitted-skew constraints;
     *         or configuration, proof planning or finite message bounds are invalid
     */
    // The apparently unused result deliberately validates overflow or representability before any side effect.
    @SuppressWarnings({ "PMD.UselessPureMethodCall" })
    public DomainSigningRequest prepare(AccessContext access, ManagedKeyProofRequest request,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(submission, "submission");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        if (ttl.isZero() || ttl.isNegative()) { throw new IllegalArgumentException("Signing lifetime must be positive"); }
        submission.createdAt().plus(ttl);
        SigningSubmissionId exact = SigningSubmissionId.parse(submission.id());
        if (!exact.equals(submission)) { throw new IllegalArgumentException("Managed key proof submission differs"); }
        String namespace = store.signingNamespace() + "." + provider.id();
        exact.validate(namespace, store.signingNow(), store.signingHorizon(), store.signingPermittedSkew());
        ProofPlan plan = plan(request, cancellation);
        FrozenChallenge frozen = challenge(plan, exact, exact.createdAt().plus(ttl), Optional.empty(), cancellation);
        byte[] challenge = frozen.content().bytes();
        DomainCommandEncoding.Decoded command = frozen.command();
        String correlation = "key-proof." + ContentCommitment.sha256(
                exact.id().value().getBytes(StandardCharsets.UTF_8)).sha256();
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.KEY_PROOF,
                correlation, ManagedKeyProofCommand.OPERATION, command.fields().toArray(String[]::new));
        return stage(access, request, exact, ttl, cancellation, challenge, template);
    }

    /**
     * Creates a preparer sharing collaborators but selecting the supplied signature identity.
     *
     * @param algorithm canonical permitted signature identity
     * @return new preparer configured for that signature
     */
    /* default */ ManagedKeyProofPreparation withSignature(String algorithm) {
        return new ManagedKeyProofPreparation(store, provider, signingAuthority, verificationAuthority, verifier,
                algorithm, random, pureEdDsaMaximum);
    }

    /**
     * Resolves the exact subject SPKI once and authorizes the shared SIGN/VERIFY binding.
     * @param request managed-key proof request; must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return method-local public-key and authorized binding metadata with no staged content
     * @throws IOException if key export, DER validation, or cancellation fails
     * @throws NullPointerException if request, cancellation, source.resolvePublicKeyInfo is null
     * @throws IllegalArgumentException if the verification profile or provider preparation capability is unavailable, or the managed public key is not bounded DER
     */
    /* default */ ProofPlan plan(ManagedKeyProofRequest request, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        String namespace = store.signingNamespace() + "." + provider.id();
        if (SignatureInteropProfiles.resolve(signature.canonicalForm()).isEmpty()) {
            throw new IllegalArgumentException("Managed key proof signature verification profile unavailable");
        }
        if (!(provider instanceof PublicKeyInfoSource source)
                || !provider.supportedAlgorithms().contains(signature.canonicalForm())) {
            throw new IllegalArgumentException("Selected provider cannot prepare managed key proof");
        }
        SigningProvider.ConfigurationCommitment configuration = provider.configurationCommitment();
        cancellation.throwIfCancelled();
        EncodedObject exported = Objects.requireNonNull(source.resolvePublicKeyInfo(request.keyRef()), "publicKeyInfo");
        cancellation.throwIfCancelled();
        if (exported.encoding() != Encoding.DER) { throw new IllegalArgumentException("Managed public key must be DER"); }
        if (exported.byteLength() < 1 || exported.byteLength() > ManagedKeyProofCommand.MAX_SPKI_BYTES) {
            throw new IllegalArgumentException("Managed public key exceeds its finite byte bound");
        }
        byte[] spki = exported.bytes();
        new StreamingDerReader().validateSubjectPublicKeyInfo(spki, ManagedKeyProofCommand.MAX_SPKI_BYTES);
        byte[] algorithm = algorithm(spki);
        List<String> metadata = new ArrayList<>(ManagedKeyProofCommand.prefix(request));
        metadata.add(namespace);
        metadata.add(HexFormat.of().formatHex(configuration.bytes()));
        metadata.add(signature.canonicalForm());
        metadata.add(HexFormat.of().formatHex(algorithm));
        return new ProofPlan(new EncodedObject(Encoding.DER, spki), metadata);
    }

    /**
     * Allocates a distinct internal proof step in the parent's namespace and creation epoch.
     * @param parent parent submission identity supplying the namespace and creation epoch
     * @return fresh internal submission identity distinct from the parent
     */
    /* default */ SigningSubmissionId newStep(SigningSubmissionId parent) {
        SigningSubmissionId step;
        do { step = SigningSubmissionId.create(parent.namespace(), parent.createdAt(), random); }
        while (step.id().equals(parent.id()));
        return step;
    }

    /**
     * Freezes a bounded challenge after the caller has frozen any parent CA intent.
     * @param plan resolved public-key and binding metadata; must not be null
     * @param step allocated internal submission identity; must not be null
     * @param deadline frozen challenge expiry instant
     * @param context optional frozen parent CA context; must not be null
     * @param cancellation cooperative cancellation signal; must not be null
     * @return bounded encoded challenge and its validated decoded command
     * @throws IOException if cancellation or challenge processing fails
     * @throws NullPointerException if plan, step, cancellation is null
     * @throws IllegalArgumentException if a responder candidate uses a CA-proof context or its pure EdDSA challenge exceeds the configured message bound
     */
    /* default */ FrozenChallenge challenge(ProofPlan plan, SigningSubmissionId step, java.time.Instant deadline,
            Optional<ManagedKeyProofChallenge.CaContext> context, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(plan, "plan");
        Objects.requireNonNull(step, "step");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        List<String> metadata = plan.metadata();
        AlgorithmIdentity signature = signingAuthority.resolveIdentity(metadata.get(8));
        byte[] spki = plan.publicKeyInfo().bytes();
        byte[] nonce = new byte[ManagedKeyProofChallenge.NONCE_BYTES];
        random.nextBytes(nonce);
        cancellation.throwIfCancelled();
        byte[] challenge;
        if (ManagedKeyProofCommand.decodePrefix(new DomainCommandEncoding.Decoded(ManagedKeyProofCommand.OPERATION, metadata))
                instanceof ManagedKeyProofRequest.OcspResponderCandidate candidate) {
            if (context.isPresent()) throw new IllegalArgumentException("Responder candidate cannot use a CA proof context");
            var target = candidate.target();
            challenge = ManagedKeyProofChallenge.encodeCandidate(step.id(), deadline,
                    new ManagedKeyProofChallenge.ResponderCandidateContext(target.parentOperationId(), target.parentIntentCommitment(),
                            target.role(), target.frozenTargetCommitment()), metadata, nonce, spki);
        } else challenge = ManagedKeyProofChallenge.encode(step.id(), deadline, context, metadata, nonce, spki);
        provider.inputCapabilities().select(signature.canonicalForm(), challenge.length);
        if ((signature.equals(BootstrapAlgorithmIdentities.ED25519_SIGNATURE)
                || signature.equals(BootstrapAlgorithmIdentities.ED448_SIGNATURE)) && challenge.length > pureEdDsaMaximum) {
            throw new IllegalArgumentException("Managed key proof exceeds the configured pure EdDSA message limit");
        }
        DomainCommandEncoding.Decoded command = ManagedKeyProofChallenge.decode(challenge).command();
        ManagedKeyProofCommand.validateAlgorithm(command, signingAuthority);
        ManagedKeyProofCommand.validateAlgorithm(command, verificationAuthority);
        return new FrozenChallenge(new EncodedObject(Encoding.BINARY, challenge), command);
    }

    /**
     * Method-local immutable public-key and binding metadata; owns no staged content.
     * @param publicKeyInfo exact bounded DER SubjectPublicKeyInfo
     * @param metadata immutable ordered binding metadata, copied on construction
     */
    /* default */ record ProofPlan(EncodedObject publicKeyInfo, List<String> metadata) {
        /**
         * Retains the exported public key and an immutable copy of binding metadata.
         *
         * @param publicKeyInfo exact exported public key; must not be null
         * @param metadata ordered metadata copied without null entries
         * @throws NullPointerException if the public key, metadata, or a metadata entry is null
         */
        ProofPlan { Objects.requireNonNull(publicKeyInfo, "publicKeyInfo"); metadata = List.copyOf(metadata); }
    }

    /**
     * Method-local immutable challenge and its exact decoded metadata.
     * @param content exact encoded challenge bytes
     * @param command decoded command validated against both authority snapshots
     */
    /* default */ record FrozenChallenge(EncodedObject content, DomainCommandEncoding.Decoded command) { }

    private byte[] algorithm(byte[] spki) {
        AlgorithmIdentity key = new BcX509AlgorithmAdapter(signingAuthority.bindings()).decode(
                Pkix.subjectPublicKeyAlgorithm(spki), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        AlgorithmIdentity verificationKey = new BcX509AlgorithmAdapter(verificationAuthority.bindings()).decode(
                Pkix.subjectPublicKeyAlgorithm(spki), X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509SuiteCompatibility.requireCompatible(signature, key);
        if (!key.equals(verificationKey)) { throw new IllegalArgumentException("Managed key proof key bindings differ"); }
        X509ExecutionPlan<SigningProvider> signing = signingAuthority.plan(signature, key, Direction.SIGN,
                Optional.empty(), "managed-key-proof", SigningProvider.class);
        signingAuthority.authorize(signing, provider, Direction.SIGN);
        X509ExecutionPlan<BcX509VerificationExecutor> verification = verificationAuthority.plan(signature, key,
                Direction.VERIFY, Optional.empty(), "managed-key-proof", BcX509VerificationExecutor.class);
        verificationAuthority.authorize(verification, verifier, Direction.VERIFY);
        byte[] algorithm = Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(signing.selection().binding()));
        byte[] expected = Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(verification.selection().binding()));
        if (!Arrays.equals(algorithm, expected)) { throw new IllegalArgumentException("Managed key proof signature bindings differ"); }
        return algorithm;
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private DomainSigningRequest stage(AccessContext access, ManagedKeyProofRequest request,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation, byte[] challenge,
            DomainContinuationTemplate template) throws IOException {
        DurableContentReference content = null;
        try {
            cancellation.throwIfCancelled();
            try (ContentSink sink = store.stagedContent().beginContent(Encoding.BINARY,
                    DurableContentReference.Lifecycle.OPERATION); OutputStream output = sink.outputStream()) {
                int offset = 0;
                while (offset < challenge.length) {
                    cancellation.throwIfCancelled();
                    int length = Math.min(16 * 1024, challenge.length - offset);
                    output.write(challenge, offset, length);
                    offset += length;
                }
                cancellation.throwIfCancelled();
                content = sink.complete();
            }
            cancellation.throwIfCancelled();
            return new DomainSigningRequest(submission.id(), access, request.keyRef(), signature.canonicalForm(),
                    Encoding.BINARY, content, ttl, template, Optional.empty());
        } catch (IOException | RuntimeException | Error primary) {
            if (content != null) {
                try { store.stagedContent().retireUnownedContent(content); }
                catch (IOException | RuntimeException cleanup) { primary.addSuppressed(cleanup); }
            }
            throw primary;
        }
    }
}
