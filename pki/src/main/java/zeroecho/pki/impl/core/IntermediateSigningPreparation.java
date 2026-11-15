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

package zeroecho.pki.impl.core; // NOPMD - CouplingBetweenObjects: one preparation authority binds issuer, profile, proof, and path contracts.

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.ArrayList;
import zeroecho.pki.impl.core.continuation.CaSigningIntent;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofChallenge;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.SignWorkflowStore;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.api.signing.ManagedKeyProofRequest;
import zeroecho.pki.impl.core.continuation.DomainAttributeEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.impl.core.continuation.IntermediateSigningCommand;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;

/**
 * Session-owned intermediate creation, issuance and lifecycle validation and single-candidate staging.
 * Borrows exact session dependencies and never signs, accepts or publishes.
 * The bounded frozen parent path is visited once (at most 31 certificates before
 * adding the child). Work is O(path bytes plus command and TBS bytes), with
 * attribute canonical validation O(A² + A log A + attribute bytes) for A IDs; preparation
 * retains O(maximum certificate plus bounded command/TBS) workspace. Store path
 * validation retains its separate existing resource contract.
 */
public final class IntermediateSigningPreparation { // NOPMD - CyclomaticComplexity totals cohesive independent operations; method-level checks remain enabled.
    private final PkiStore store;
    private final SigningProvider provider;
    private final X509AuthoritySnapshot authority;
    private final X509AlgorithmBindingRegistry bindings;
    private final AlgorithmIdentity signature;
    private final EffectiveCredentialStatusResolver status;
    private final ManagedKeyProofPreparation proofs;
    private final long pureEdDsaMaximum;

    /**
     * Binds to the already-opened provider and exact SIGN authority.
     * @param store authoritative session store
     * @param clock evaluation clock
     * @param provider selected already-opened provider
     * @param authority SIGN authority bound to that provider
     * @param bindings exact installed X.509 binding registry
     * @param signatureAlgorithm canonical configured signature identity
     * @param pureEdDsaMaximum inclusive pure-EdDSA input bound in bytes
     * @param proofs shared session preparation using the exact SIGN/VERIFY authorities
     */
    public IntermediateSigningPreparation(PkiStore store, Clock clock, SigningProvider provider,
            X509AuthoritySnapshot authority, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm,
            long pureEdDsaMaximum, ManagedKeyProofPreparation proofs) {
        this.store = Objects.requireNonNull(store, "store");
        this.provider = Objects.requireNonNull(provider, "provider");
        this.authority = Objects.requireNonNull(authority, "authority");
        this.bindings = Objects.requireNonNull(bindings, "bindings");
        signature = authority.resolveIdentity(signatureAlgorithm);
        if (signature.kind() != AlgorithmIdentity.Kind.SIGNATURE || !signature.canonicalForm().equals(signatureAlgorithm)) {
            throw new IllegalArgumentException("Configured signing identity is invalid");
        }
        X509SecurityFloor.requirePermitted(signature);
        FullCrlSigningCommand.requireAdmission("", 0, pureEdDsaMaximum);
        this.pureEdDsaMaximum = pureEdDsaMaximum;
        status = new StoreBackedEffectiveCredentialStatusResolver(store, Objects.requireNonNull(clock, "clock"));
        this.proofs = Objects.requireNonNull(proofs, "proofs");
    }

    /**
     * Validates current issuer/path, profile, subject and managed public-key
     * metadata without signatures, proof staging, serial allocation or CA mutation.
     * Execution repeats all checks and obtains its own fresh proof and serial.
     *
     * @param access separately authenticated and authorized invocation context
     * @param input immutable intermediate creation coordinates
     * @param cancellation cooperative validation cancellation
     * @throws IOException if public metadata cannot be read or validation is cancelled
     * @throws RuntimeException if issuer, profile, subject, key or algorithm policy rejects input
     */
    public void validate(AccessContext access, IntermediateCreateCommand input,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        IntermediateInput publicInput = readInput(input, cancellation);
        ValidatedCaCertificateRequest approved = validateProfile(input, publicInput,
                new PkiId("preflight:intermediate"), BigInteger.ONE);
        validatedTbs(publicInput.parent(), publicInput.proof(), approved, false);
        cancellation.throwIfCancelled();
    }

    private IntermediateInput readInput(IntermediateCreateCommand input, CancellationSignal cancellation) throws IOException {
        EffectiveCredentialStatusResolver.Evaluation evaluation = status.beginEvaluation();
        CaRecord ca = store.getCa(input.issuerCaId()).orElseThrow(() -> reject("ISSUER_MISSING"));
        if (!ca.caId().equals(input.issuerCaId()) || ca.state() != CaState.ACTIVE) throw reject("ISSUER_INACTIVE");
        IssuerGeneration generation = IssuerAuthorities.current(store, ca);
        IssuerChainPath path = IssuerAuthorities.issuancePath(store, ca);
        if (path.orderedCredentialIds().size() >= IssuerChainPath.MAX_CERTIFICATES) throw reject("PATH_TOO_LONG");
        Credential issuer = store.getCredential(generation.credentialId()).orElseThrow(() -> reject("ISSUER_CREDENTIAL_MISSING"));
        requireIssuer(ca, generation, path, issuer);
        evaluation.requireUsable(issuer, CredentialUse.INTERMEDIATE_ISSUER);
        ActiveCertificateProfile profile = store.requireActiveProfile(input.profileId());
        if (!profile.reference().profileId().equals(input.profileId())
                || !input.formatId().equals(BcX509CredentialFramework.FORMAT_ID)) throw reject("PROFILE_BINDING_INVALID");
        CaCertificateProfileValidator.requireProfileShape(profile, CertificateProfileKind.INTERMEDIATE_CA, input.formatId());
        requireManagedSubjectProfile(profile);
        ManagedKeyProofPreparation.ProofPlan proof = proofs.withSignature(input.signatureAlgorithmId().orElse(signature.canonicalForm()))
                .plan(new ManagedKeyProofRequest.CaSubject(
                        ca.caId(), Optional.empty(), input.profileId(), input.keyRef()), cancellation);
        if (generation.signingKeyRef().equals(input.keyRef())) throw reject("SUBJECT_KEY_IS_PARENT_KEY");
        List<SubjectRdn> subject = CaCertificateProfileValidator.validateSubject(input.subjectRef(), profile.definition());
        X509Certificate parent = path(path, issuer, BcX509ProfileSupport.subject(subject), evaluation.evaluationTime(), cancellation);
        return new IntermediateInput(evaluation.evaluationTime(), ca, generation, path, issuer, profile, proof, subject, parent);
    }

    private ValidatedCaCertificateRequest validateProfile(IntermediateCreateCommand input, IntermediateInput publicInput,
            PkiId child, BigInteger serial) {
        return CaCertificateProfileValidator.validateApprovedSubject(
                ValidatedCaCertificateRequest.Operation.CREATE_INTERMEDIATE, publicInput.profile(), CertificateProfileKind.INTERMEDIATE_CA,
                input.formatId(), publicInput.ca().caId(), child, publicInput.subject(), publicInput.proof().publicKeyInfo(),
                Optional.empty(), publicInput.evaluationTime().truncatedTo(ChronoUnit.SECONDS),
                Optional.of(publicInput.parent().getNotAfter().toInstant()), serial, authority)
                .withFrozenPublication(publicInput.generation().issuerId(), publicInput.path().pathId(),
                        publicInput.path().pathCommitment(), input.keyRef());
    }

    private byte[] validatedTbs(X509Certificate parent, ManagedKeyProofPreparation.ProofPlan proof,
            ValidatedCaCertificateRequest approved, boolean signAlternative) throws IOException {
        return validatedTbs(parent, proof, approved, signAlternative, Optional.empty());
    }

    private byte[] validatedTbs(X509Certificate parent, ManagedKeyProofPreparation.ProofPlan proof,
            ValidatedCaCertificateRequest approved, boolean signAlternative,
            Optional<zeroecho.pki.impl.core.continuation.CaOutgoingBinding> subjectOutgoing) throws IOException {
        AlgorithmIdentity signature = issuerSignature(approved.issuerCaId());
        AlgorithmIdentifier algorithm = algorithm(parent, approved);
        Validity validity = wholeSecondValidity(approved.validity());
        var builder = Pkix.certificateBuilder().serialNumber(approved.serial()).issuer(parent.getSubjectX500Principal())
                .subject(BcX509ProfileSupport.subject(approved.subjectRdns())).publicKeyInfo(proof.publicKeyInfo().bytes())
                .validity(validity.notBefore(), validity.notAfter())
                .basicConstraints(BasicConstraints.ca(approved.policy().pathLengthConstraint()), approved.policy().basicConstraintsCritical())
                .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), approved.policy().keyUsageCritical());
        ActiveCertificateProfile profile = store.requireActiveProfile(approved.profileReference().profileId());
        if (profile.definition().hybridMode() instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature mode) {
            if (!(provider instanceof zeroecho.pki.spi.crypto.PublicKeyInfoSource keys)
                    || !(provider instanceof zeroecho.pki.spi.crypto.AltSigningCapability signer)) throw reject("ALT_SIGNING_CAPABILITY_UNAVAILABLE");
            var ca = store.getCa(approved.issuerCaId()).orElseThrow(() -> reject("ISSUER_MISSING"));
            var parentBinding = issuerBinding(IssuerAuthorities.current(store, ca)).alternative()
                    .orElseThrow(() -> reject("ALT_ISSUER_BINDING_MISSING"));
            KeyRef subjectAlternativeRef = subjectOutgoing.flatMap(value -> value.alternative())
                    .map(zeroecho.pki.api.ca.IssuerKeyBinding::keyRef).orElseGet(() -> new KeyRef(mode.altKeyRef()));
            byte[] subjectAlternative = keys.resolvePublicKeyInfo(subjectAlternativeRef).bytes();
            if (subjectOutgoing.isPresent() && !hash(subjectAlternative).equals(subjectOutgoing.orElseThrow()
                    .alternative().orElseThrow(() -> reject("ALT_SUBJECT_ROLE_MISSING")).subjectSpkiSha256())) {
                throw reject("ALT_SUBJECT_KEY_CHANGED");
            }
            var altAlgorithm = Pkix.parseAlgorithmIdentifier(parentBinding.signatureAlgorithmIdentifier().bytes());
            builder.addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.subjectAltPublicKeyInfo(subjectAlternative))
                    .addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.altSignatureAlgorithm(altAlgorithm));
            byte[] input = builder.buildAlternativeSignatureTbs(algorithm);
            // Pure validation exercises public policy and capability planning, never a signer.
            byte[] alternativeSignature = new byte[alternativeSignatureLength(parentBinding.signatureAlgorithm())];
            if (signAlternative) {
                var plan = authority.plan(parentBinding.signatureAlgorithm(), parentBinding.publicKeyAlgorithm(), Direction.SIGN,
                        Optional.empty(), "explicit", SigningProvider.class);
                authority.authorize(plan, provider, Direction.SIGN);
                try { alternativeSignature = signer.sign(parentBinding.keyRef(), parentBinding.signatureAlgorithm().canonicalForm(), input); }
                catch (java.security.GeneralSecurityException failure) { throw new PkiException("ALT_SIGNING_FAILED", failure); }
                byte[] issuerSpki = zeroecho.pki.impl.hybrid.AltSignatureExtensions.requiredValue(parent, "2.5.29.72");
                var verifier = Pkix.verifier(issuerSpki, altAlgorithm);
                try (var output = verifier.contentStream()) { output.write(input); }
                if (!verifier.verify(alternativeSignature)) throw reject("ALT_SIGNATURE_INVALID");
            }
            builder.addExtension(zeroecho.pki.impl.hybrid.AltSignatureExtensions.altSignatureValue(alternativeSignature));
        }
        byte[] tbs = builder.buildTbs(algorithm);
        if (tbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) throw reject("TBS_TOO_LARGE");
        provider.inputCapabilities().select(signature.canonicalForm(), tbs.length);
        FullCrlSigningCommand.requireAdmission(signature.canonicalForm(), tbs.length, pureEdDsaMaximum);
        return tbs;
    }

    private String incoming(IssuerGeneration generation) {
        var binding = issuerBinding(generation);
        return new zeroecho.pki.impl.core.continuation.CaOutgoingBinding(binding.primary(), Optional.empty(),
                binding.bindingSetCommitment()).encodeForSubject();
    }

    private static int alternativeSignatureLength(AlgorithmIdentity algorithm) {
        if (algorithm.family().name().equals("ml-dsa-87")) return 4627;
        if (algorithm.family().name().equals("ml-dsa-65")) return 3309;
        // Size is an admission estimate only; execution checks the actual encoded body.
        return 512;
    }

    private record IntermediateInput(java.time.Instant evaluationTime, CaRecord ca, IssuerGeneration generation,
            IssuerChainPath path, Credential issuer, ActiveCertificateProfile profile,
            ManagedKeyProofPreparation.ProofPlan proof, List<SubjectRdn> subject, X509Certificate parent) { }

    /**
     * Freezes one authorized invocation's issuer, profile, proof-bound subject key
     * and TBS. The caller must authorize the operation separately. A successful
     * return transfers both unowned candidates; failed adoption must retire both.
     * No serial is reserved until the existing acceptance transaction.
     * @param access trusted invocation context
     * @param input immutable intermediate creation command
     * @param submission fresh internally allocated submission ID
     * @param ttl configured positive signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged domain request
     * @throws IOException if staging, content access or cancellation fails
     * @throws RuntimeException if issuer, profile, proof, path or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, IntermediateCreateCommand input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(submission, "submission");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        validateSubmission(submission, ttl);
        IntermediateInput publicInput = readInput(input, cancellation);
        CaRecord ca = publicInput.ca();
        IssuerGeneration generation = publicInput.generation();
        IssuerChainPath path = publicInput.path();
        Credential issuer = publicInput.issuer();
        ActiveCertificateProfile profile = publicInput.profile();
        ManagedKeyProofPreparation.ProofPlan proof = publicInput.proof();
        X509Certificate parent = publicInput.parent();
        List<SubjectRdn> subject = publicInput.subject();
        PkiId child = authorityId(submission.id());
        BigInteger serial = CertificateSerialAllocator.allocate();
        ValidatedCaCertificateRequest approved = validateProfile(input, publicInput, child, serial);
        X500Principal exactSubject = BcX509ProfileSupport.subject(subject);
        byte[] tbs = validatedTbs(parent, proof, approved, true);
        List<String> fields = List.of(input.formatId().value(), ca.caId().value(),
                child.value(), generation.issuerId().value(), path.pathId().value(), path.pathCommitment(), input.keyRef().value(),
                profile.reference().profileId(), Long.toString(profile.reference().profileVersion()),
                HexFormat.of().formatHex(profile.reference().canonicalSha256()), exactSubject.getName(X500Principal.RFC2253),
                approved.validity().notBefore().toString(), approved.validity().notAfter().toString(), serial.toString(),
                generation.signingKeyRef().value(), issuer.content().contentId(), issuer.content().sha256(),
                hash(proof.publicKeyInfo().bytes()), "", "",
                DomainAttributeEncoding.encode(input.attributes()), Integer.toString(tbs.length), hash(tbs),
                outgoing(profile, input.keyRef(), proof).encodeForSubject(), incoming(generation));
        return stage(access, submission, ttl, generation, IntermediateSigningCommand.CREATE, fields, proof, tbs, cancellation);
    }

    /**
     * Freezes additional issuance for an active existing intermediate authority.
     * Its expected key must match the authoritative current key, and the internal
     * proof binds the exact parent, subject, requested profile and key. The
     * authoritative subject principal is preserved, including fixed RDNs.
     * Generic attributes are rejected. Preparation neither signs nor accepts work;
     * later publication appends a generation without changing issuance selection.
     * @param access separately authorized invocation context
     * @param input immutable existing-authority issuance command
     * @param submission fresh internally allocated submission identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged domain request requiring adoption or retirement
     * @throws IOException if content access, staging or cancellation fails
     * @throws RuntimeException if authoritative state, profile, proof, path or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, IntermediateCertIssueCommand input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(input, "input");
        return prepareExisting(access, new ExistingRequest(input.subjectCaId(), input.issuerCaId(), input.keyRef(),
                Optional.of(new ExplicitProfile(input.formatId(), input.profileId())), true,
                input.requestedValidity(), input.attributes(), ValidatedCaCertificateRequest.Operation.ISSUE_INTERMEDIATE,
                Optional.empty(), input.expectedHead()),
                submission, ttl, cancellation);
    }

    /**
     * Prepares renewal under the active version of the selected credential's CA
     * profile. The expected subject key must still be authoritative. The internal
     * proof binds the exact parent, existing subject, profile and key. Publication
     * selects the new generation/path while retaining historical generations.
     * @param access separately authorized invocation context
     * @param input existing intermediate rollover coordinates
     * @param submission fresh internally allocated signing identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged request requiring adoption or retirement
     * @throws IOException if content access, staging or cancellation fails
     * @throws RuntimeException if authority, profile, proof, path or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, CaRolloverCommand.Intermediate input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(input, "input");
        return prepareExisting(access, new ExistingRequest(input.caId(), input.issuerCaId(), input.keyRef(),
                Optional.empty(), true, input.requestedValidity(), input.attributes(),
                ValidatedCaCertificateRequest.Operation.ROLLOVER_INTERMEDIATE, Optional.empty(), input.expectedHead()), submission, ttl, cancellation);
    }

    /**
     * Prepares rotation using the supplied managed key and the active version of
     * the selected credential's CA profile. The supplied key may equal the current
     * key. No old-credential expiry/revocation gate or old-key proof is added.
     * @param access separately authorized invocation context
     * @param input intermediate, parent, replacement-key coordinates
     * @param submission fresh internally allocated signing identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged request requiring adoption or retirement
     * @throws IOException if content access, staging or cancellation fails
     * @throws RuntimeException if authority, profile, proof, path or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, CaKeyRotationCommand.Intermediate input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(input, "input");
        return prepareExisting(access, rotationRequest(input), submission, ttl, cancellation);
    }

    private record ExplicitProfile(FormatId formatId, String profileId) { }
    private record ExistingRequest(PkiId subjectCaId, PkiId issuerCaId, KeyRef keyRef,
            Optional<ExplicitProfile> profile, boolean requireCurrentKey, Optional<Validity> requestedValidity,
            AttributeSet attributes, ValidatedCaCertificateRequest.Operation operation,
            Optional<zeroecho.pki.api.ca.CaRotationSelection> selection,
            Optional<zeroecho.pki.api.ca.CaHeadSnapshot> expectedHead) {
        private ExistingRequest(PkiId subjectCaId, PkiId issuerCaId, KeyRef keyRef,
                Optional<ExplicitProfile> profile, boolean requireCurrentKey, Optional<Validity> requestedValidity,
                AttributeSet attributes, ValidatedCaCertificateRequest.Operation operation) {
            this(subjectCaId, issuerCaId, keyRef, profile, requireCurrentKey, requestedValidity, attributes, operation,
                    Optional.empty(), Optional.empty());
        }
    }

    private ExistingRequest rotationRequest(CaKeyRotationCommand.Intermediate input) {
        CaRecord subject = store.getCa(input.caId()).orElseThrow(() -> reject("SUBJECT_MISSING"));
        var binding = store.getIssuerCryptographicBinding(subject.currentIssuanceIssuerId())
                .orElseThrow(() -> reject("SUBJECT_BINDING_MISSING"));
        var effective = input.selection().effective(binding);
        if (input.expectedHead().isPresent() && !input.expectedHead().orElseThrow().equals(
                store.getCaHeadSnapshot(input.caId()).orElseThrow(() -> reject("CA_HEAD_EVIDENCE_MISSING")))) {
            throw reject("CA_EXPECTED_HEAD_CONFLICT");
        }
        return new ExistingRequest(input.caId(), input.issuerCaId(), effective.primary().orElseThrow().keyRef().orElseThrow(),
                Optional.empty(), false, Optional.empty(), input.attributes(), ValidatedCaCertificateRequest.Operation.ROLLOVER_INTERMEDIATE,
                Optional.of(effective), input.expectedHead());
    }

    private DomainSigningRequest prepareExisting(AccessContext access, ExistingRequest input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(submission, "submission");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        validateSubmission(submission, ttl);
        ExistingIntermediate existing = readExisting(input, CertificateSerialAllocator.allocate(), cancellation);
        CaRecord subject = existing.subject(); CaRecord ca = existing.ca();
        IssuerGeneration generation = existing.generation(); IssuerChainPath path = existing.path();
        AlgorithmIdentity signature = issuerBinding(generation).primary().signatureAlgorithm();
        Credential issuer = existing.issuer(); ActiveCertificateProfile profile = existing.profile();
        ManagedKeyProofPreparation.ProofPlan proof = existing.proof(); X509Certificate parent = existing.parent();
        X500Principal subjectPrincipal = existing.subjectPrincipal();
        String profileId = profile.reference().profileId(); FormatId formatId = existing.formatId();
        ValidatedCaCertificateRequest approved = existing.approved(); BigInteger serial = approved.serial();
        Validity validity = wholeSecondValidity(approved.validity());
        AlgorithmIdentifier algorithm = algorithm(parent, approved);
        byte[] tbs = validatedTbs(parent, proof, approved, true, Optional.of(existing.outgoing()));
        List<String> fields = new ArrayList<>(List.of(formatId.value(), ca.caId().value(),
                subject.caId().value(), generation.issuerId().value(), path.pathId().value(), path.pathCommitment(), input.keyRef().value(),
                profile.reference().profileId(), Long.toString(profile.reference().profileVersion()),
                HexFormat.of().formatHex(profile.reference().canonicalSha256()), subject.subjectRef().value(),
                validity.notBefore().toString(), validity.notAfter().toString(), serial.toString(),
                generation.signingKeyRef().value(), issuer.content().contentId(), issuer.content().sha256(),
                hash(proof.publicKeyInfo().bytes()), "", "",
                DomainAttributeEncoding.encode(input.attributes()), Integer.toString(tbs.length), hash(tbs),
                existing.outgoing().encodeForSubject(), incoming(generation)));
        fields.add(zeroecho.pki.impl.core.continuation.CaLifecycleContextCodec.encode(existing.lifecycle()));
        return stage(access, submission, ttl, generation, input.operation().name(), fields, proof, tbs, cancellation);
    }

    /**
     * Validates issuance input without serial allocation, signing, staging or acceptance.
     * @param access trusted invocation context
     * @param command typed issuance input
     * @param cancellation cooperative cancellation
     * @throws IOException if authoritative content cannot be read
     * @throws RuntimeException if input or authoritative state is invalid
     */
    public void validateExisting(AccessContext access, IntermediateCertIssueCommand command, CancellationSignal cancellation) throws IOException {
        validateExistingInput(access, command, cancellation);
    }

    /**
     * Validates rollover input without serial allocation, signing, staging or acceptance.
     * @param access trusted invocation context
     * @param command typed rollover input
     * @param cancellation cooperative cancellation
     * @throws IOException if authoritative content cannot be read
     * @throws RuntimeException if input or authoritative state is invalid
     */
    public void validateExisting(AccessContext access, CaRolloverCommand.Intermediate command, CancellationSignal cancellation) throws IOException {
        validateExistingInput(access, command, cancellation);
    }

    /**
     * Validates rotation input without serial allocation, signing, staging or acceptance.
     * @param access trusted invocation context
     * @param command typed rotation input
     * @param cancellation cooperative cancellation
     * @throws IOException if authoritative content cannot be read
     * @throws RuntimeException if input or authoritative state is invalid
     */
    public void validateExisting(AccessContext access, CaKeyRotationCommand.Intermediate command, CancellationSignal cancellation) throws IOException {
        validateExistingInput(access, command, cancellation);
    }

    private void validateExistingInput(AccessContext access, Object command, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        ExistingRequest input;
        if (command instanceof IntermediateCertIssueCommand value) {
            input = new ExistingRequest(value.subjectCaId(), value.issuerCaId(), value.keyRef(),
                    Optional.of(new ExplicitProfile(value.formatId(), value.profileId())), true,
                    value.requestedValidity(), value.attributes(), ValidatedCaCertificateRequest.Operation.ISSUE_INTERMEDIATE,
                    Optional.empty(), value.expectedHead());
        } else if (command instanceof CaRolloverCommand.Intermediate value) {
            input = new ExistingRequest(value.caId(), value.issuerCaId(), value.keyRef(), Optional.empty(), true,
                    value.requestedValidity(), value.attributes(), ValidatedCaCertificateRequest.Operation.ROLLOVER_INTERMEDIATE,
                    Optional.empty(), value.expectedHead());
        } else if (command instanceof CaKeyRotationCommand.Intermediate value) {
            input = rotationRequest(value);
        } else { throw new UnsupportedOperationException("Unsupported intermediate lifecycle input"); }
        ExistingIntermediate existing = readExisting(input, BigInteger.ONE, cancellation);
        validatedTbs(existing.parent(), existing.proof(), existing.approved(), false, Optional.of(existing.outgoing()));
        cancellation.throwIfCancelled();
    }

    private ExistingIntermediate readExisting(ExistingRequest input, BigInteger serial,
            CancellationSignal cancellation) throws IOException {
        if (!input.attributes().ids().isEmpty()) { throw reject("ATTRIBUTES_NOT_SUPPORTED"); }
        EffectiveCredentialStatusResolver.Evaluation evaluation = status.beginEvaluation();
        CaRecord subject = existingSubject(input);
        var capturedHead = store.getCaHeadSnapshot(subject.caId()).orElseThrow(() -> reject("CA_HEAD_EVIDENCE_MISSING"));
        if (input.expectedHead().isPresent() && !input.expectedHead().orElseThrow().equals(capturedHead)
                || !capturedHead.issuerId().equals(subject.currentIssuanceIssuerId())
                || !capturedHead.pathId().equals(subject.issuanceChainPathId())) throw reject("CA_EXPECTED_HEAD_CONFLICT");
        CaRecord ca = store.getCa(input.issuerCaId()).orElseThrow(() -> reject("ISSUER_MISSING"));
        if (!ca.caId().equals(input.issuerCaId()) || ca.state() != CaState.ACTIVE) { throw reject("ISSUER_INACTIVE"); }
        IssuerGeneration generation = IssuerAuthorities.current(store, ca);
        IssuerChainPath path = IssuerAuthorities.issuancePath(store, ca);
        if (path.orderedCredentialIds().size() >= IssuerChainPath.MAX_CERTIFICATES) { throw reject("PATH_TOO_LONG"); }
        Credential issuer = store.getCredential(generation.credentialId()).orElseThrow(() -> reject("ISSUER_CREDENTIAL_MISSING"));
        requireIssuer(ca, generation, path, issuer);
        evaluation.requireUsable(issuer, CredentialUse.INTERMEDIATE_ISSUER);
        ExplicitProfile selectedProfile = existingProfile(input, subject);
        String profileId = selectedProfile.profileId();
        FormatId formatId = selectedProfile.formatId();
        ActiveCertificateProfile profile = store.requireActiveProfile(profileId);
        if (!profile.reference().profileId().equals(profileId)
                || !formatId.equals(BcX509CredentialFramework.FORMAT_ID)) { throw reject("PROFILE_BINDING_INVALID"); }
        CaCertificateProfileValidator.requireProfileShape(profile, CertificateProfileKind.INTERMEDIATE_CA, formatId);
        requireManagedSubjectProfile(profile);
        var subjectGeneration = IssuerAuthorities.current(store, subject);
        var subjectBinding = store.getIssuerCryptographicBinding(subjectGeneration.issuerId())
                .orElseThrow(() -> reject("SUBJECT_BINDING_MISSING"));
        if ((profile.definition().hybridMode() instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature)
                != subjectBinding.alternative().isPresent()) {
            throw reject("HYBRID_MODE_CHANGE_UNSUPPORTED");
        }
        if (!capturedHead.bindingCommitment().equals(subjectBinding.commitment())) throw reject("CA_EXPECTED_HEAD_CONFLICT");
        var effectiveSelection = input.selection().orElseGet(() ->
                zeroecho.pki.api.ca.CaRotationSelection.primaryKey(subjectBinding.primary().keyRef()).effective(subjectBinding));
        String selectedSubjectAlgorithm = effectiveSelection.primary().orElseThrow().signatureAlgorithmId().orElseThrow();
        ManagedKeyProofPreparation.ProofPlan proof = proofs.withSignature(selectedSubjectAlgorithm)
                .plan(new ManagedKeyProofRequest.CaSubject(ca.caId(), Optional.of(subject.caId()), profileId, input.keyRef()), cancellation);
        if (!(provider instanceof zeroecho.pki.spi.crypto.PublicKeyInfoSource subjectKeys)) throw reject("PUBLIC_KEY_SOURCE_MISSING");
        IssuerBindingResolver.resolve(store, subjectGeneration,
                reference -> reference.equals(input.keyRef()) ? proof.publicKeyInfo() : subjectKeys.resolvePublicKeyInfo(reference), authority);
        Credential currentSubject = IssuerAuthorities.currentCredential(store, subject);
        byte[] currentDer = CredentialContent.materializeForBc(store, currentSubject.content());
        if (!hash(currentDer).equals(currentSubject.content().sha256())
                || !subject.subjectRef().equals(currentSubject.subjectRef())) { throw reject("SUBJECT_CONTENT_DIFFERS"); }
        new StreamingDerReader().validate(currentDer, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
        X509Certificate currentCertificate = Pkix.parseCertificate(currentDer);
        requirePathMetadata(currentCertificate, currentSubject);
        X500Principal subjectPrincipal = currentCertificate.getSubjectX500Principal();
        List<SubjectRdn> subjectRdns = CaCertificateProfileValidator.validateTrustedSubject(subjectPrincipal, profile.definition());
        X509Certificate parent = path(path, issuer, subjectPrincipal, evaluation.evaluationTime(), cancellation);
        ValidatedCaCertificateRequest approved = CaCertificateProfileValidator.validateApprovedSubject(
                input.operation(), profile, CertificateProfileKind.INTERMEDIATE_CA,
                formatId, ca.caId(), subject.caId(), subjectRdns, proof.publicKeyInfo(), input.requestedValidity(),
                evaluation.evaluationTime(), Optional.of(parent.getNotAfter().toInstant()), serial, authority)
                .withFrozenPublication(generation.issuerId(), path.pathId(), path.pathCommitment(), input.keyRef());
        var outgoing = outgoing(profile, input.keyRef(), proof, Optional.of(effectiveSelection));
        var lifecycle = new zeroecho.pki.impl.core.continuation.CaLifecycleContext(1,
                input.selection().isPresent() ? zeroecho.pki.impl.core.continuation.CaLifecycleContext.Operation.INTERMEDIATE_ROTATION
                        : input.operation() == ValidatedCaCertificateRequest.Operation.ISSUE_INTERMEDIATE
                                ? zeroecho.pki.impl.core.continuation.CaLifecycleContext.Operation.INTERMEDIATE_ISSUE
                                : zeroecho.pki.impl.core.continuation.CaLifecycleContext.Operation.INTERMEDIATE_ROLLOVER,
                capturedHead, currentSubject.credentialId(), currentSubject.content().sha256(), Optional.empty());
        return new ExistingIntermediate(subject, ca, generation, path, issuer, profile, proof, parent,
                subjectPrincipal, formatId, approved, outgoing, lifecycle);
    }

    private record ExistingIntermediate(CaRecord subject, CaRecord ca, IssuerGeneration generation,
            IssuerChainPath path, Credential issuer, ActiveCertificateProfile profile,
            ManagedKeyProofPreparation.ProofPlan proof, X509Certificate parent,
            X500Principal subjectPrincipal, FormatId formatId, ValidatedCaCertificateRequest approved,
            zeroecho.pki.impl.core.continuation.CaOutgoingBinding outgoing,
            zeroecho.pki.impl.core.continuation.CaLifecycleContext lifecycle) { }

    private X509Certificate path(IssuerChainPath path, Credential issuer, X500Principal childSubject,
            Instant now, CancellationSignal cancellation) throws IOException {
        X509Certificate parent = null;
        X509Certificate previous = null;
        int below = 0;
        StreamingDerReader derReader = new StreamingDerReader();
        for (PkiId id : path.orderedCredentialIds()) {
            cancellation.throwIfCancelled();
            Credential credential = id.equals(issuer.credentialId()) ? issuer
                    : store.getCredential(id).orElseThrow(() -> reject("PATH_CREDENTIAL_MISSING"));
            if (!credential.credentialId().equals(id) || !credential.formatId().equals(BcX509CredentialFramework.FORMAT_ID)) {
                throw reject("PATH_CREDENTIAL_DIFFERS");
            }
            byte[] der = CredentialContent.materializeForBc(store, credential.content());
            if (!hash(der).equals(credential.content().sha256())) { throw reject("PATH_CONTENT_DIFFERS"); }
            derReader.validate(der, CredentialContent.MAXIMUM_CERTIFICATE_BYTES);
            X509Certificate current = Pkix.parseCertificate(der);
            requirePathMetadata(current, credential);
            if (parent == null) {
                parent = current;
                requireParentUsable(parent, now);
                below = childSubject.equals(parent.getSubjectX500Principal()) ? 0 : 1;
            } else if (!previous.getIssuerX500Principal().equals(current.getSubjectX500Principal())) {
                throw reject("PATH_RELATIONSHIP_DIFFERS");
            }
            // Owner policy A includes the anchor, and counts non-self-issued CAs only.
            if (below > current.getBasicConstraints()) { throw reject("PATH_LENGTH_EXCEEDED"); }
            if (!current.getIssuerX500Principal().equals(current.getSubjectX500Principal())) { below++; }
            previous = current;
        }
        cancellation.throwIfCancelled();
        return Objects.requireNonNull(parent, "parent");
    }

    // Overflow and identifier representability are checked before staging or provider access.
    @SuppressWarnings("PMD.UselessPureMethodCall")
    private void validateSubmission(SigningSubmissionId submission, Duration ttl) {
        if (ttl.isNegative() || ttl.isZero()) { throw reject("LIFETIME_INVALID"); }
        submission.createdAt().plus(ttl);
        if (!SigningSubmissionId.parse(submission.id()).equals(submission)) { throw reject("SUBMISSION_INVALID"); }
        submission.validate(store.signingNamespace() + "." + provider.id(), store.signingNow(),
                store.signingHorizon(), store.signingPermittedSkew());
    }

    private static Validity wholeSecondValidity(Validity approved) {
        Instant start = approved.notBefore().truncatedTo(ChronoUnit.SECONDS);
        if (start.isBefore(approved.notBefore())) { start = start.plusSeconds(1); }
        Instant end = approved.notAfter().truncatedTo(ChronoUnit.SECONDS);
        if (!end.isAfter(start)) { throw reject("VALIDITY_NOT_REPRESENTABLE"); }
        return new Validity(start, end);
    }

    private ExplicitProfile existingProfile(ExistingRequest input, CaRecord subject) {
        if (input.profile().isPresent()) { return input.profile().orElseThrow(); }
        Credential selected = IssuerAuthorities.currentCredential(store, subject);
        if (!(selected.profileBinding() instanceof CaProfileBinding historical)) {
            throw reject("SUBJECT_PROFILE_BINDING_INVALID");
        }
        return new ExplicitProfile(selected.formatId(), historical.reference().profileId());
    }

    private static void requirePathMetadata(X509Certificate current, Credential credential) {
        if (current.getBasicConstraints() < 0
                || !matchesSubject(current.getSubjectX500Principal(), credential.subjectRef().value())
                || !current.getNotBefore().toInstant().equals(credential.validity().notBefore())
                || !current.getNotAfter().toInstant().equals(credential.validity().notAfter())
                || !current.getSerialNumber().toString().equals(credential.serialOrUniqueId())) { throw reject("PATH_METADATA_DIFFERS"); }
    }

    private static boolean matchesSubject(X500Principal subject, String frozen) {
        return frozen.equals(subject.getName(X500Principal.RFC2253))
                || frozen.equals(Pkix.distinguishedNameString(Pkix.parseDistinguishedName(subject.getEncoded())));
    }

    private static void requireParentUsable(X509Certificate parent, Instant now) {
        boolean[] usage = parent.getKeyUsage();
        if (usage == null || usage.length <= 5 || !usage[5]
                || now.isBefore(parent.getNotBefore().toInstant()) || !now.isBefore(parent.getNotAfter().toInstant())) {
            throw reject("ISSUER_CERTIFICATE_UNUSABLE");
        }
    }

    private zeroecho.pki.impl.core.continuation.CaOutgoingBinding outgoing(ActiveCertificateProfile profile,
            KeyRef keyRef, ManagedKeyProofPreparation.ProofPlan proof) throws IOException {
        return outgoing(profile, keyRef, proof, Optional.empty());
    }

    private zeroecho.pki.impl.core.continuation.CaOutgoingBinding outgoing(ActiveCertificateProfile profile,
            KeyRef keyRef, ManagedKeyProofPreparation.ProofPlan proof,
            Optional<zeroecho.pki.api.ca.CaRotationSelection> selection) throws IOException {
        if (!(provider instanceof zeroecho.pki.spi.crypto.PublicKeyInfoSource keys)) throw reject("PUBLIC_KEY_SOURCE_MISSING");
        var primary = IssuerBindingResolver.createKey(keyRef, authority.resolveIdentity(proof.metadata().get(8)),
                proof.publicKeyInfo().bytes(), reference -> {
                    if (!keyRef.equals(reference)) throw reject("SUBJECT_KEY_REFERENCE_DIFFERS");
                    return proof.publicKeyInfo();
                }, authority);
        Optional<zeroecho.pki.api.ca.IssuerKeyBinding> alternative = Optional.empty();
        if (profile.definition().hybridMode() instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature mode) {
            var selected = selection.flatMap(value -> value.alternative());
            KeyRef reference = selected.flatMap(zeroecho.pki.api.ca.CaRotationSelection.RoleChange::keyRef)
                    .orElseGet(() -> new KeyRef(mode.altKeyRef()));
            String selectedAlgorithm = selected.flatMap(zeroecho.pki.api.ca.CaRotationSelection.RoleChange::signatureAlgorithmId)
                    .orElse(mode.altSignatureAlgorithmId());
            alternative = Optional.of(IssuerBindingResolver.createKey(reference, authority.resolveIdentity(selectedAlgorithm),
                    keys.resolvePublicKeyInfo(reference).bytes(), keys, authority));
        }
        return new zeroecho.pki.impl.core.continuation.CaOutgoingBinding(primary, alternative, bindings.commitment());
    }

    private static void requireManagedSubjectProfile(ActiveCertificateProfile profile) {
        if (profile.definition().hybridMode() instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature mode
                && mode.subjectKeySource() != zeroecho.pki.api.hybrid.HybridCertificateMode.AlternativeSubjectKeySource.MANAGED) {
            throw reject("MANAGED_CA_SUBJECT_REQUIRED");
        }
    }

    private zeroecho.pki.api.ca.IssuerCryptographicBinding issuerBinding(IssuerGeneration generation) {
        if (!(provider instanceof zeroecho.pki.spi.crypto.PublicKeyInfoSource keys)) throw reject("PUBLIC_KEY_SOURCE_MISSING");
        return IssuerBindingResolver.resolve(store, generation, keys, authority);
    }
    private AlgorithmIdentity issuerSignature(PkiId caId) {
        CaRecord ca = store.getCa(caId).orElseThrow(() -> reject("ISSUER_MISSING"));
        return issuerBinding(IssuerAuthorities.current(store, ca)).primary().signatureAlgorithm();
    }

    private AlgorithmIdentifier algorithm(X509Certificate parent, ValidatedCaCertificateRequest request) {
        CaRecord parentAuthority = store.getCa(request.issuerCaId()).orElseThrow(() -> reject("ISSUER_MISSING"));
        var captured = issuerBinding(IssuerAuthorities.current(store, parentAuthority));
        AlgorithmIdentity signature = captured.primary().signatureAlgorithm();
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentity parentKey = adapter.decode(Pkix.subjectPublicKeyAlgorithm(Pkix.subjectPublicKeyInfo(parent)),
                X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509SuiteCompatibility.requireCompatible(signature, parentKey);
        X509AlgorithmBindingPolicy policy = request.algorithmBindingPolicy();
        X509AlgorithmBinding binding = binding(signature, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE, policy.certificateSignature());
        X509ExecutionPlan<SigningProvider> plan = authority.plan(signature, parentKey, Direction.SIGN, Optional.empty(),
                "explicit", binding.bindingId(), SigningProvider.class);
        authority.authorize(plan, provider, Direction.SIGN);
        AlgorithmIdentifier subjectAlgorithm = Pkix.subjectPublicKeyAlgorithm(request.exactPublicKey().bytes());
        AlgorithmIdentity subjectKey = adapter.decode(subjectAlgorithm, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509AlgorithmBinding subjectBinding = binding(subjectKey, X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY, policy.subjectPublicKey());
        AlgorithmIdentifier expected = BcX509AlgorithmAdapter.toLib(authority.bindings().resolve(subjectBinding.bindingId(),
                subjectKey, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM));
        if (!subjectAlgorithm.equals(expected)) { throw reject("SUBJECT_BINDING_DIFFERS"); }
        AlgorithmIdentifier exact = BcX509AlgorithmAdapter.toLib(plan.selection().binding());
        if (!exact.equals(Pkix.parseAlgorithmIdentifier(captured.primary().signatureAlgorithmIdentifier().bytes()))) {
            throw reject("ISSUER_SIGNATURE_BINDING_DIFFERS");
        }
        return exact;
    }

    private X509AlgorithmBinding binding(AlgorithmIdentity identity, X509AlgorithmBinding.Role role,
            Optional<X509AlgorithmBindingPolicy.BindingReference> reference) {
        X509AlgorithmBinding selected = reference.map(value -> bindings.require(value.bindingId(), value.semanticCommitment()))
                .orElseGet(() -> bindings.standard(identity, role).orElseThrow(() -> reject("BINDING_MISSING")));
        if (selected.role() != role || !selected.algorithmIdentity().equals(identity)
                || reference.isPresent() && selected.origin() == X509AlgorithmBinding.Origin.STANDARD) { throw reject("BINDING_DIFFERS"); }
        return selected;
    }

    private static void requireIssuer(CaRecord ca, IssuerGeneration generation, IssuerChainPath path, Credential credential) {
        if (!credential.credentialId().equals(generation.credentialId())
                || !path.orderedCredentialIds().getFirst().equals(credential.credentialId())
                || !ca.issuerKeyRef().equals(generation.signingKeyRef()) || !ca.subjectRef().equals(credential.subjectRef())
                || !(credential.profileBinding() instanceof CaProfileBinding profile)
                || !generation.profilePolicyCommitment().equals(HexFormat.of().formatHex(profile.reference().canonicalSha256()))
                ) { throw reject("ISSUER_BINDING_DIFFERS"); }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private DomainSigningRequest stage(AccessContext access, SigningSubmissionId submission, Duration ttl,
            IssuerGeneration parent, String operation, List<String> immutableFields, ManagedKeyProofPreparation.ProofPlan plan,
            byte[] tbs, CancellationSignal cancellation) throws IOException {
        AlgorithmIdentity signature = issuerBinding(parent).primary().signatureAlgorithm();
        String intent = CaSigningIntent.commitment(new DomainCommandEncoding.Decoded(operation, immutableFields), signature);
        var captured = zeroecho.pki.impl.core.continuation.CaOutgoingBinding.decodeForSubject(immutableFields.get(23),
                new KeyRef(immutableFields.get(6)));
        Optional<ManagedKeyProofPreparation.ProofPlan> alternativePlan = Optional.empty();
        if (captured.alternative().isPresent()) {
            var selected = captured.alternative().orElseThrow();
            alternativePlan = Optional.of(proofs.withSignature(selected.signatureAlgorithm().canonicalForm())
                    .plan(new ManagedKeyProofRequest.CaSubject(parent.authorityId(),
                            IntermediateSigningCommand.CREATE.equals(operation) ? Optional.empty()
                                    : Optional.of(new PkiId(immutableFields.get(2))), immutableFields.get(7), selected.keyRef()), cancellation));
        }
        String lifecycle = immutableFields.size() == 26
                ? zeroecho.pki.impl.core.continuation.CaLifecycleContextCodec.commitment(
                        zeroecho.pki.impl.core.continuation.CaLifecycleContextCodec.decode(immutableFields.get(25)))
                : intent.substring("ca-intent:v1:".length());
        SigningSubmissionId step = proofs.newStep(submission);
        var primaryContext = alternativePlan.isEmpty() ? new ManagedKeyProofChallenge.CaContext(submission.id(), intent)
                : new ManagedKeyProofChallenge.CaContext(submission.id(), intent,
                        Optional.of(SignWorkflowStore.SubjectKeyRole.PRIMARY), Optional.of(lifecycle));
        ManagedKeyProofPreparation.FrozenChallenge proof = proofs.challenge(plan, step, submission.createdAt().plus(ttl),
                Optional.of(primaryContext), cancellation);
        Optional<SigningSubmissionId> alternativeStep = alternativePlan.map(ignored -> proofs.newStep(submission));
        Optional<ManagedKeyProofPreparation.FrozenChallenge> alternativeProof = Optional.empty();
        if (alternativePlan.isPresent()) {
            alternativeProof = Optional.of(proofs.challenge(alternativePlan.orElseThrow(), alternativeStep.orElseThrow(),
                    submission.createdAt().plus(ttl), Optional.of(new ManagedKeyProofChallenge.CaContext(submission.id(), intent,
                            Optional.of(SignWorkflowStore.SubjectKeyRole.ALTERNATIVE), Optional.of(lifecycle))), cancellation));
        }
        List<String> fields = new ArrayList<>(immutableFields);
        fields.set(18, step.id().value());
        var primaryCommand = DomainCommandEncoding.template(DomainContinuationStore.Kind.KEY_PROOF,
                ManagedKeyProofCommand.OPERATION, proof.command().fields().toArray(String[]::new)).command();
        fields.set(19, alternativeProof.isEmpty() ? IntermediateSigningCommand.encodeProof(primaryCommand)
                : IntermediateSigningCommand.encodeProofs(step.id(), primaryCommand, alternativeStep.orElseThrow().id(),
                        DomainCommandEncoding.template(DomainContinuationStore.Kind.KEY_PROOF, ManagedKeyProofCommand.OPERATION,
                                alternativeProof.orElseThrow().command().fields().toArray(String[]::new)).command()));
        DomainContinuationTemplate template = IntermediateSigningCommand.template(operation, "intermediate." + hash(
                submission.id().value().getBytes(StandardCharsets.UTF_8)), fields);
        DurableContentReference content = null;
        DurableContentReference challenge = null;
        DurableContentReference alternativeChallenge = null;
        try {
            content = stageCandidate(tbs, Encoding.DER, cancellation);
            challenge = stageCandidate(proof.content().bytes(), Encoding.BINARY, cancellation);
            if (alternativeProof.isPresent()) alternativeChallenge = stageCandidate(alternativeProof.orElseThrow().content().bytes(), Encoding.BINARY, cancellation);
            cancellation.throwIfCancelled();
            SignWorkflowStore.CaSubjectProofStep descriptor = new SignWorkflowStore.CaSubjectProofStep(step.id(),
                    new KeyRef(proof.command().field(5)), proof.command().field(8), challenge);
            Optional<SignWorkflowStore.CaSubjectProofStep> alternativeDescriptor = Optional.empty();
            if (alternativeProof.isPresent()) {
                var exact = alternativeProof.orElseThrow();
                alternativeDescriptor = Optional.of(new SignWorkflowStore.CaSubjectProofStep(alternativeStep.orElseThrow().id(),
                        new KeyRef(exact.command().field(5)), exact.command().field(8), alternativeChallenge,
                        SignWorkflowStore.SubjectKeyRole.ALTERNATIVE));
            }
            return new DomainSigningRequest(submission.id(), access, parent.signingKeyRef(), signature.canonicalForm(),
                    Encoding.BINARY, content, ttl, template, Optional.of(descriptor), alternativeDescriptor);
        } catch (IOException | RuntimeException | Error primary) {
            retireAfterFailure(content, primary);
            retireAfterFailure(challenge, primary);
            retireAfterFailure(alternativeChallenge, primary);
            throw primary;
        }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private DurableContentReference stageCandidate(byte[] bytes, Encoding encoding, CancellationSignal cancellation) throws IOException {
        DurableContentReference completed = null;
        try {
            cancellation.throwIfCancelled();
            try (ContentSink sink = store.stagedContent().beginContent(encoding, DurableContentReference.Lifecycle.OPERATION);
                    OutputStream output = sink.outputStream()) {
                int offset = 0;
                while (offset < bytes.length) {
                    cancellation.throwIfCancelled();
                    int count = Math.min(16 * 1024, bytes.length - offset);
                    output.write(bytes, offset, count);
                    offset += count;
                }
                cancellation.throwIfCancelled();
                completed = sink.complete();
            }
            cancellation.throwIfCancelled();
            return completed;
        } catch (IOException | RuntimeException | Error primary) {
            retireAfterFailure(completed, primary);
            throw primary;
        }
    }

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private void retireAfterFailure(DurableContentReference candidate, Throwable primary) {
        if (candidate != null) {
            try { store.stagedContent().retireUnownedContent(candidate); }
            catch (IOException | RuntimeException | Error cleanup) { primary.addSuppressed(cleanup); }
        }
    }

    private static PkiId authorityId(PkiId operation) {
        return new PkiId("ca:" + hash(("zeroecho:pki:intermediate-authority:v1\0" + operation.value()).getBytes(StandardCharsets.UTF_8)));
    }
    private static String hash(byte[] bytes) { return SigningProvider.ContentCommitment.sha256(bytes).sha256(); }
    private static PkiException reject(String code) { return new PkiException("Intermediate creation rejected: code=" + code); }

    private CaRecord existingSubject(ExistingRequest input) {
        CaRecord subject = store.getCa(input.subjectCaId()).orElseThrow(() -> reject("SUBJECT_MISSING"));
        if (!subject.caId().equals(input.subjectCaId()) || subject.kind() != CaKind.INTERMEDIATE
                || subject.state() != CaState.ACTIVE) { throw reject("SUBJECT_UNAVAILABLE"); }
        if (input.requireCurrentKey() && !subject.issuerKeyRef().equals(input.keyRef())) { throw reject("SUBJECT_KEY_CHANGED"); }
        return subject;
    }
}
