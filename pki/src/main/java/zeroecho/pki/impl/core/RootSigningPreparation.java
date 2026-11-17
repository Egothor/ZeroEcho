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

import java.util.Arrays;
import zeroecho.pki.api.ca.CaHeadSnapshot;
import zeroecho.pki.api.ca.CaRotationSelection;
import zeroecho.pki.api.ca.IssuerCryptographicBinding;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pki.api.ca.RootTrustAnchorTransition;
import zeroecho.pki.impl.core.continuation.CaLifecycleContext;
import zeroecho.pki.impl.core.continuation.CaLifecycleContextCodec;
import zeroecho.pki.impl.core.continuation.CaOutgoingBinding;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.spi.crypto.AltSigningCapability;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;

/**
 * Validates and stages one self-issued root TBS using borrowed session dependencies.
 * Preparation does not accept primary-signing work or publish CA metadata.
 * AltSignature preparation synchronously obtains and verifies the alternative
 * signature before staging the primary-signing candidate. The eventual primary self-signature is verified by the
 * existing terminal publisher against the public key frozen in this TBS.
 * Local time and auxiliary memory are O(K + S + T + E) for bounded public-key,
 * subject, TBS and command bytes, plus existing provider/planning/store work;
 * staging writes O(T) bytes and performs no authority inventory scan.
 *
 * <p>The store, provider and authority snapshot are borrowed and remain owned by
 * the session. This component resolves existing managed public keys; it neither
 * generates keys nor imports private material. Root possession is established by
 * the eventual verified self-signature rather than a separate subject-proof child
 * prepared here. Candidate construction does not install an external trust anchor,
 * acknowledge distribution or perform durable root activation.</p>
 */
public final class RootSigningPreparation { // NOPMD CyclomaticComplexity - Aggregate lifecycle/coordinator complexity; individual methods remain checked.
    private final PkiStore store;
    private final Clock clock;
    private final SigningProvider provider;
    private final X509AuthoritySnapshot authority;
    private final X509AlgorithmBindingRegistry bindings;
    private final AlgorithmIdentity signature;
    private final long pureEdDsaMaximum;

    /**
     * Binds root preparation to the selected provider and its exact SIGN authority.
     * @param store authoritative session store
     * @param clock clock supplying one profile-evaluation instant per preparation
     * @param provider selected already-opened provider and public-key source
     * @param authority SIGN authority bound to that provider
     * @param bindings exact installed X.509 binding registry
     * @param signatureAlgorithm canonical configured signature identity
     * @param pureEdDsaMaximum inclusive pure-EdDSA input bound, from 1 through Integer.MAX_VALUE minus 8 bytes
     * @throws NullPointerException if a required session dependency or signature identity is null
     * @throws IllegalArgumentException if the configured identity cannot be resolved canonically,
     *     is not a permitted signature identity or the pure-EdDSA bound is outside its finite range
     */
    public RootSigningPreparation(PkiStore store, Clock clock, SigningProvider provider,
            X509AuthoritySnapshot authority, X509AlgorithmBindingRegistry bindings, String signatureAlgorithm,
            long pureEdDsaMaximum) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
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
    }

    /**
     * Returns the canonical creation signature selected when this preparer was bound.
     *
     * <p>This accessor performs no lookup or mutation. An individual creation command
     * can select a different explicit identity; existing-root operations resolve
     * their effective identity from retained outgoing roles and the rotation selector.</p>
     *
     * @return exact configured canonical signature identity
     */
    public String creationSignatureAlgorithm() { return signature.canonicalForm(); }

    private RootSigningPreparation selected(CaCreateCommand input) {
        String selected = input.signatureAlgorithmId().orElse(signature.canonicalForm());
        return selected.equals(signature.canonicalForm()) ? this : new RootSigningPreparation(store, clock, provider,
                authority, bindings, selected, pureEdDsaMaximum);
    }

    /**
     * Validates the currently known root inputs without serial allocation,
     * content staging, provider signing or authority mutation. Alternative keys
     * are checked as public metadata only; their signature is never requested.
     * Execution repeats these checks and validates its exact generated TBS size.
     *
     * @param access separately authenticated and authorized invocation context
     * @param input immutable root creation input
     * @param cancellation cooperative validation cancellation
     * @throws IOException if public metadata cannot be read or validation is cancelled
     * @throws RuntimeException if access, input or cancellation is null; or the profile, subject, key or algorithm is invalid
     */
    // Delegation is selected by object identity to avoid recursive self-delegation.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    public void validate(AccessContext access, CaCreateCommand input,
            CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        RootSigningPreparation selected = selected(input);
        if (selected != this) {
            selected.validate(access, input, cancellation);
            return;
        }
        RootInput publicInput = readInput(input, cancellation);
        // These local coordinates exercise policy without consuming a real serial or operation ID.
        PkiId validationId = new PkiId("preflight:root");
        ValidatedCaCertificateRequest approved = validateProfile(input, publicInput, validationId,
                BigInteger.ONE, clock.instant());
        validateTbs(input.altKeyRef(), publicInput.profile(), publicInput.spki(), approved, cancellation);
        cancellation.throwIfCancelled();
    }

    private void validateTbs(Optional<KeyRef> alternativeKey, ActiveCertificateProfile profile, byte[] spki,
            ValidatedCaCertificateRequest approved, CancellationSignal cancellation) throws IOException {
        validateTbs(alternativeKey, profile.definition().hybridMode(), spki, approved, cancellation);
    }

    private void validateTbs(Optional<KeyRef> alternativeKey, HybridCertificateMode mode, byte[] spki,
            ValidatedCaCertificateRequest approved, CancellationSignal cancellation) throws IOException {
        RootCertificateEncoding.wholeSecondValidity(approved.validity());
        encoding().algorithm(approved);
        if (mode instanceof HybridCertificateMode.AltSignature alternative) {
            encoding().publicKeyInfo(alternativeKey.orElseGet(() -> new KeyRef(alternative.altKeyRef())), cancellation);
            AlgorithmIdentity identity = authority.resolveIdentity(alternative.altSignatureAlgorithmId());
            if (identity.kind() != AlgorithmIdentity.Kind.SIGNATURE) { throw reject("ALT_ALGORITHM_INVALID"); }
            X509SecurityFloor.requirePermitted(identity);
            bindings.standard(identity, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE)
                    .orElseThrow(() -> reject("ALT_ALGORITHM_BINDING_MISSING"));
            if (!(provider instanceof AltSigningCapability)) { throw reject("ALT_SIGNING_CAPABILITY_UNAVAILABLE"); }
        } else {
            Validity validity = RootCertificateEncoding.wholeSecondValidity(approved.validity());
            byte[] tbs = encoding().buildTbs(alternativeKey, mode, approved,
                    encoding().algorithm(approved), BcX509ProfileSupport.subject(approved.subjectRdns()), spki,
                    validity, cancellation);
            if (tbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) { throw reject("TBS_TOO_LARGE"); }
            provider.inputCapabilities().select(signature.canonicalForm(), tbs.length);
            FullCrlSigningCommand.requireAdmission(signature.canonicalForm(), tbs.length, pureEdDsaMaximum);
        }
    }

    private RootInput readInput(CaCreateCommand input, CancellationSignal cancellation) throws IOException {
        ActiveCertificateProfile profile = store.requireActiveProfile(input.profileId());
        if (!profile.reference().profileId().equals(input.profileId())
                || !input.formatId().equals(BcX509CredentialFramework.FORMAT_ID)) { throw reject("PROFILE_BINDING_INVALID"); }
        CaCertificateProfileValidator.requireProfileShape(profile, CertificateProfileKind.ROOT_CA, input.formatId());
        if (!input.attributes().ids().isEmpty()) { throw reject("ATTRIBUTES_NOT_SUPPORTED"); }
        return new RootInput(profile, encoding().publicKeyInfo(input.keyRef(), cancellation));
    }

    private ValidatedCaCertificateRequest validateProfile(CaCreateCommand input, RootInput publicInput,
            PkiId root, BigInteger serial, Instant evaluationTime) {
        return CaCertificateProfileValidator.validate(
                ValidatedCaCertificateRequest.Operation.CREATE_ROOT, publicInput.profile(), CertificateProfileKind.ROOT_CA,
                input.formatId(), root, root, input.subjectRef(), new EncodedObject(Encoding.DER, publicInput.spki()),
                Optional.empty(), evaluationTime, Optional.empty(), serial, authority);
    }

    private record RootInput(ActiveCertificateProfile profile, byte[] spki) { }

    /**
     * Freezes the exact active root profile, approved subject and one provider SPKI
     * into a single unsigned certificate candidate. Whole-second validity narrows
     * the approved interval. All policy, algorithm and size checks precede staging.
     * A successful return transfers one unowned candidate to the caller, which must
     * adopt or retire it; the access context is preserved without granting authority.
     *
     * <p>AltSignature preparation can already have produced and verified an alternative
     * signature before staging begins. On a later failure, completed unowned staged
     * content is retired when possible and cleanup failures are suppressed onto the
     * original failure. Cleanup cannot undo a signature already produced by a provider.</p>
     *
     * @param access separately authenticated and authorized invocation context
     * @param input immutable root creation command with an existing managed key
     * @param submission fresh internally allocated submission identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged root signing request
     * @throws IOException if DER validation, staging or cancellation fails
     * @throws RuntimeException if access, input, submission, ttl or cancellation is null;
     *         ttl is nonpositive or produces an unrepresentable deadline; submission
     * is noncanonical or violates namespace, horizon or permitted-skew constraints; or profile, subject, provider, key,
     * binding or bounds are invalid
     */
    // Delegation is selected by object identity to avoid recursive self-delegation.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    public DomainSigningRequest prepare(AccessContext access, CaCreateCommand input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(submission, "submission");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        RootSigningPreparation selected = selected(input);
        if (selected != this) { return selected.prepare(access, input, submission, ttl, cancellation); }
        validateSubmission(submission, ttl);
        Instant evaluationTime = clock.instant();
        RootInput publicInput = readInput(input, cancellation);
        ActiveCertificateProfile profile = publicInput.profile();
        byte[] spki = publicInput.spki();
        PkiId root = DomainCommandEncoding.rootAuthorityId(submission.id());
        BigInteger serial = CertificateSerialAllocator.allocate();
        ValidatedCaCertificateRequest approved = validateProfile(input, publicInput, root, serial, evaluationTime);
        Validity validity = RootCertificateEncoding.wholeSecondValidity(approved.validity());
        AlgorithmIdentifier algorithm = encoding().algorithm(approved);
        X500Principal subject = BcX509ProfileSupport.subject(approved.subjectRdns());
        byte[] tbs = encoding().buildTbs(input.altKeyRef(), profile.definition().hybridMode(), approved, algorithm, subject, spki,
                validity, cancellation);
        if (tbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) { throw reject("TBS_TOO_LARGE"); }
        provider.inputCapabilities().select(signature.canonicalForm(), tbs.length);
        FullCrlSigningCommand.requireAdmission(signature.canonicalForm(), tbs.length, pureEdDsaMaximum);
        String correlation = "root." + SigningProvider.ContentCommitment.sha256(
                submission.id().value().getBytes(StandardCharsets.UTF_8)).sha256();
        String canonicalSubject = subject.getName(X500Principal.RFC2253);
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.CA,
                correlation, "CREATE_ROOT", input.formatId().value(), canonicalSubject, input.profileId(),
                input.keyRef().value(), profile.reference().profileId(), Long.toString(profile.reference().profileVersion()),
                HexFormat.of().formatHex(profile.reference().canonicalSha256()), validity.notBefore().toString(),
                validity.notAfter().toString(), serial.toString(), canonicalSubject,
                approved.policy().toString(), approved.algorithmBindingPolicy().toString(), root.value(),
                outgoing(profile, input.keyRef(), input.altKeyRef(), spki).encodeForSubject());
        return stage(access, input.keyRef(), submission, ttl, template, tbs, cancellation);
    }

    /**
     * Prepares root rollover using the authoritative current key and the active
     * version of the selected credential's profile. The old credential supplies
     * profile identity only; its expiry/revocation does not cap or veto renewal.
     * This internal root-typed primitive does not provide a public lifecycle dispatcher.
     *
     * <p>The retained outgoing algorithms and alternative role are authoritative;
     * the current creation default and an old profile's key reference do not replace
     * them. A supplied expected head must match, and the exact original head is
     * captured in the returned lifecycle context for later admission. Preparation
     * does not conditionally replace that head.</p>
     *
     * @param access separately authorized invocation context
     * @param input root identifier and optional policy-checked validity
     * @param submission fresh internally allocated submission identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged request requiring adoption or retirement
     * @throws IOException if DER validation, staging or cancellation fails
     * @throws RuntimeException if access, input, submission, ttl or cancellation is null;
     *         ttl is nonpositive or produces an unrepresentable deadline; submission
     * is noncanonical or violates namespace, horizon or permitted-skew constraints; or authority, profile, key,
     * bindings or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, CaRolloverCommand.Root input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(input, "input");
        return prepareExisting(access, input.caId(), Optional.empty(), input.expectedHead(), input.requestedValidity(), input.attributes(),
                submission, ttl, cancellation);
    }

    /**
     * Prepares root rotation from explicit outgoing-role changes and the active profile.
     *
     * <p>Partial and algorithm-only selectors are resolved against the retained
     * generation binding, so a role can retain its managed key while changing its
     * signature algorithm. Reusing the current key reference is permitted. Both
     * selected AltSignature roles must preserve the profile's hybrid family; the
     * alternative key is retained or replaced according to the effective selector,
     * and a fresh alternative signature is produced and verified.</p>
     *
     * <p>A changed public key, public-key algorithm, signature identity or signature
     * DER in either outgoing role marks a fresh root candidate. The exact original
     * head and transition identity are frozen for later publication and activation.
     * The returned TBS still requires its verified primary self-signature. No old-key
     * proof, separate managed subject-proof child, primary-signing dispatch, CA head
     * replacement, external trust distribution or activation occurs here.</p>
     *
     * @param access separately authorized invocation context
     * @param input root identifier, outgoing-role changes and optional original-head fence
     * @param submission fresh internally allocated submission identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged request requiring adoption or retirement
     * @throws IOException if DER validation, staging or cancellation fails
     * @throws RuntimeException if access, input, submission, ttl or cancellation is null;
     *         ttl is nonpositive or produces an unrepresentable deadline; submission
     * is noncanonical or violates namespace, horizon or permitted-skew constraints; or authority, profile, key,
     * bindings or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, CaKeyRotationCommand.Root input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(input, "input");
        return prepareExisting(access, input.caId(), Optional.of(input.selection()), input.expectedHead(), Optional.empty(), input.attributes(),
                submission, ttl, cancellation);
    }

    private DomainSigningRequest prepareExisting(AccessContext access, PkiId caId,
            Optional<CaRotationSelection> rotation,
            Optional<CaHeadSnapshot> expectedHead, Optional<Validity> requestedValidity, AttributeSet attributes, SigningSubmissionId submission,
            Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(submission, "submission");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        CaRecord current = store.getCa(caId).orElseThrow(() -> reject("ROOT_MISSING"));
        Optional<IssuerCryptographicBinding> retained = store.getIssuerCryptographicBinding(current.currentIssuanceIssuerId());
        if (retained.isEmpty()) { throw reject("ISSUER_BINDING_MISSING"); }
        requireExpectedHead(caId, expectedHead);
        Optional<CaRotationSelection> effective = rotation.map(value -> value.effective(retained.orElseThrow()));
        String selectedAlgorithm = effective.flatMap(CaRotationSelection::primary)
                .flatMap(CaRotationSelection.RoleChange::signatureAlgorithmId)
                .orElse(retained.orElseThrow().primary().signatureAlgorithm().canonicalForm());
        if (!signature.canonicalForm().equals(selectedAlgorithm)) {
            return new RootSigningPreparation(store, clock, provider, authority, bindings,
                    selectedAlgorithm, pureEdDsaMaximum).prepareExisting(access, caId, rotation, expectedHead,
                            requestedValidity, attributes, submission, ttl, cancellation);
        }
        Optional<KeyRef> replacementKey = effective.flatMap(CaRotationSelection::primary)
                .flatMap(CaRotationSelection.RoleChange::keyRef);
        validateSubmission(submission, ttl);
        ExistingRoot existing = readExisting(caId, replacementKey, requestedValidity, attributes,
                CertificateSerialAllocator.allocate(), cancellation);
        CaHeadSnapshot capturedHead = store.getCaHeadSnapshot(caId).orElseThrow(() -> reject("CA_HEAD_EVIDENCE_MISSING"));
        if (expectedHead.isPresent() && !expectedHead.orElseThrow().equals(capturedHead)
                || !capturedHead.issuerId().equals(current.currentIssuanceIssuerId())
                || !capturedHead.pathId().equals(current.issuanceChainPathId())
                || !capturedHead.bindingCommitment().equals(retained.orElseThrow().commitment())
                || !store.getIssuerGeneration(capturedHead.issuerId()).orElseThrow(() -> reject("ISSUER_BINDING_MISSING"))
                        .credentialId().equals(existing.selected().credentialId())) { throw reject("CA_EXPECTED_HEAD_CONFLICT"); }
        Credential selected = existing.selected();
        ActiveCertificateProfile profile = existing.profile();
        KeyRef keyRef = existing.keyRef();
        byte[] spki = existing.spki();
        X500Principal subject = existing.subject();
        ValidatedCaCertificateRequest approved = existing.approved();
        BigInteger serial = approved.serial();
        Validity validity = RootCertificateEncoding.wholeSecondValidity(approved.validity());
        AlgorithmIdentifier algorithm = encoding().algorithm(approved);
        HybridCertificateMode selectedMode = selectedMode(profile, effective, retained.orElseThrow());
        CaOutgoingBinding capturedOutgoing = outgoing(keyRef, Optional.empty(), spki, selectedMode);
        boolean candidate = !sameAnchorRole(retained.orElseThrow().primary(), capturedOutgoing.primary())
                || !retained.orElseThrow().alternative().map(old -> capturedOutgoing.alternative()
                        .filter(next -> sameAnchorRole(old, next)).isPresent()).orElse(capturedOutgoing.alternative().isEmpty());
        CaLifecycleContext context = new CaLifecycleContext(1, candidate
                ? CaLifecycleContext.Operation.ROOT_CANDIDATE
                : CaLifecycleContext.Operation.ROOT_ROLLOVER,
                capturedHead, selected.credentialId(), selected.content().sha256(), candidate
                        ? Optional.of(RootTrustAnchorTransition.idFor(submission.id())) : Optional.empty());
        byte[] tbs = encoding().buildTbs(Optional.empty(), selectedMode, approved, algorithm, subject,
                spki, validity, cancellation);
        if (tbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) { throw reject("TBS_TOO_LARGE"); }
        provider.inputCapabilities().select(signature.canonicalForm(), tbs.length);
        FullCrlSigningCommand.requireAdmission(signature.canonicalForm(), tbs.length, pureEdDsaMaximum);
        String correlation = "root." + SigningProvider.ContentCommitment.sha256(
                submission.id().value().getBytes(StandardCharsets.UTF_8)).sha256();
        String canonicalSubject = subject.getName(X500Principal.RFC2253);
        DomainContinuationTemplate template = DomainCommandEncoding.correlatedTemplate(DomainContinuationStore.Kind.CA,
                correlation, "ROLLOVER_ROOT", selected.formatId().value(), canonicalSubject, profile.reference().profileId(),
                keyRef.value(), profile.reference().profileId(), Long.toString(profile.reference().profileVersion()),
                HexFormat.of().formatHex(profile.reference().canonicalSha256()), validity.notBefore().toString(),
                validity.notAfter().toString(), serial.toString(), canonicalSubject,
                approved.policy().toString(), approved.algorithmBindingPolicy().toString(), caId.value(),
                capturedOutgoing.encodeForSubject(), CaLifecycleContextCodec.encode(context));
        return stage(access, keyRef, submission, ttl, template, tbs, cancellation);
    }

    /**
     * Validates current root rollover policy without allocating a serial, signing or staging.
     *
     * <p>Reads the selected credential and retained binding, checks an optional
     * expected head, active profile and public-key continuity, and evaluates a local
     * provisional serial. This is a current-state preflight; preparation repeats its
     * checks and freezes the actual original head and generated TBS.</p>
     *
     * @param access trusted invocation context
     * @param command typed rollover input
     * @param cancellation cooperative cancellation
     * @throws IOException if authoritative content cannot be read
     * @throws RuntimeException if input or authoritative state is invalid
     */
    public void validateExisting(AccessContext access, CaRolloverCommand.Root command, CancellationSignal cancellation) throws IOException {
        validateExistingInput(access, command, cancellation);
    }

    /**
     * Validates effective root role changes without allocating a serial, signing or staging.
     *
     * <p>Resolves partial selectors against the retained generation, checks optional
     * original-head evidence and validates public inputs under the active profile.
     * Alternative-role preflight checks metadata and capability without obtaining an
     * alternative signature; preparation must still validate its actual signed TBS.
     * No rotation, candidate completion or activation is admitted by this check.</p>
     *
     * @param access trusted invocation context
     * @param command typed rotation input
     * @param cancellation cooperative cancellation
     * @throws IOException if authoritative content cannot be read
     * @throws RuntimeException if input or authoritative state is invalid
     */
    public void validateExisting(AccessContext access, CaKeyRotationCommand.Root command, CancellationSignal cancellation) throws IOException {
        validateExistingInput(access, command, cancellation);
    }

    private void validateExistingInput(AccessContext access, Object command, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        PkiId caId = command instanceof CaRolloverCommand.Root value ? value.caId()
                : command instanceof CaKeyRotationCommand.Root value ? value.caId() : null;
        if (caId == null) { throw new UnsupportedOperationException("Unsupported root lifecycle input"); }
        CaRecord ca = store.getCa(caId).orElseThrow(() -> reject("ROOT_MISSING"));
        IssuerCryptographicBinding retained = store.getIssuerCryptographicBinding(ca.currentIssuanceIssuerId()).orElseThrow(() -> reject("ISSUER_BINDING_MISSING"));
        Optional<CaRotationSelection> effective = command instanceof CaKeyRotationCommand.Root value
                ? Optional.of(value.selection().effective(retained)) : Optional.empty();
        if (command instanceof CaKeyRotationCommand.Root value) { requireExpectedHead(caId, value.expectedHead()); }
        if (command instanceof CaRolloverCommand.Root value) { requireExpectedHead(caId, value.expectedHead()); }
        String selectedAlgorithm = effective.flatMap(CaRotationSelection::primary)
                .flatMap(CaRotationSelection.RoleChange::signatureAlgorithmId)
                .orElse(retained.primary().signatureAlgorithm().canonicalForm());
        if (!signature.canonicalForm().equals(selectedAlgorithm)) {
            new RootSigningPreparation(store, clock, provider, authority, bindings,
                    selectedAlgorithm, pureEdDsaMaximum)
                    .validateExistingInput(access, command, cancellation);
            return;
        }
        ExistingRoot existing;
        if (command instanceof CaRolloverCommand.Root input) {
            existing = readExisting(input.caId(), Optional.empty(), input.requestedValidity(), input.attributes(), BigInteger.ONE, cancellation);
        } else if (command instanceof CaKeyRotationCommand.Root input) {
            existing = readExisting(input.caId(), effective.flatMap(CaRotationSelection::primary)
                    .flatMap(CaRotationSelection.RoleChange::keyRef),
                    Optional.empty(), input.attributes(), BigInteger.ONE, cancellation);
        } else { throw new UnsupportedOperationException("Unsupported root lifecycle input"); }
        validateTbs(Optional.empty(), selectedMode(existing.profile(), effective, retained), existing.spki(), existing.approved(), cancellation);
        cancellation.throwIfCancelled();
    }

    private static boolean sameAnchorRole(IssuerKeyBinding old,
            IssuerKeyBinding next) {
        return old.subjectSpkiSha256().equals(next.subjectSpkiSha256())
                && old.publicKeyAlgorithm().equals(next.publicKeyAlgorithm())
                && old.signatureAlgorithm().equals(next.signatureAlgorithm())
                && Arrays.equals(old.signatureAlgorithmIdentifier().bytes(), next.signatureAlgorithmIdentifier().bytes());
    }

    private void requireExpectedHead(PkiId caId, Optional<CaHeadSnapshot> expected) {
        if (expected.isPresent() && !expected.orElseThrow().equals(store.getCaHeadSnapshot(caId).orElseThrow(
                () -> reject("CA_HEAD_EVIDENCE_MISSING")))) { throw reject("CA_EXPECTED_HEAD_CONFLICT"); }
    }

    private static HybridCertificateMode selectedMode(ActiveCertificateProfile profile,
            Optional<CaRotationSelection> effective,
            IssuerCryptographicBinding retained) {
        HybridCertificateMode mode = profile.definition().hybridMode();
        if (mode instanceof HybridCertificateMode.AltSignature) {
            if (effective.isEmpty()) {
                IssuerKeyBinding current = retained.alternative().orElseThrow(() -> reject("ALT_ROLE_CONTINUITY_INVALID"));
                return new HybridCertificateMode.AltSignature(current.signatureAlgorithm().canonicalForm(), current.keyRef().value());
            }
            CaRotationSelection.RoleChange selected = effective.orElseThrow().alternative().orElseThrow(() -> reject("ALT_ROLE_CONTINUITY_INVALID"));
            return new HybridCertificateMode.AltSignature(selected.signatureAlgorithmId().orElseThrow(),
                    selected.keyRef().orElseThrow().value());
        }
        if (effective.flatMap(CaRotationSelection::alternative).isPresent())
            { throw reject("HYBRID_MODE_CHANGE_UNSUPPORTED"); }
        return mode;
    }

    private ExistingRoot readExisting(PkiId caId, Optional<KeyRef> replacementKey, Optional<Validity> requestedValidity,
            AttributeSet attributes, BigInteger serial, CancellationSignal cancellation) throws IOException {
        if (!attributes.ids().isEmpty()) { throw reject("ATTRIBUTES_NOT_SUPPORTED"); }
        Instant evaluationTime = clock.instant();
        CaRecord root = store.getCa(caId).orElseThrow(() -> reject("ROOT_MISSING"));
        if (!root.caId().equals(caId) || root.kind() != CaKind.ROOT || root.state() != CaState.ACTIVE) {
            throw reject("ROOT_UNAVAILABLE");
        }
        if (!(provider instanceof PublicKeyInfoSource keys)) { throw reject("PUBLIC_KEY_SOURCE_MISSING"); }
        IssuerGeneration generation = IssuerAuthorities.current(store, root);
        EncodedObject issuerPublicKey = keys.resolvePublicKeyInfo(generation.signingKeyRef());
        IssuerBindingResolver.resolve(store, generation,
                reference -> reference.equals(generation.signingKeyRef()) ? issuerPublicKey : keys.resolvePublicKeyInfo(reference), authority);
        Credential selected = IssuerAuthorities.currentCredential(store, root);
        if (!(selected.profileBinding() instanceof CaProfileBinding historical)) { throw reject("ROOT_PROFILE_BINDING_INVALID"); }
        ActiveCertificateProfile profile = store.requireActiveProfile(historical.reference().profileId());
        if (!profile.reference().profileId().equals(historical.reference().profileId())
                || !selected.formatId().equals(BcX509CredentialFramework.FORMAT_ID)) { throw reject("PROFILE_BINDING_INVALID"); }
        CaCertificateProfileValidator.requireProfileShape(profile, CertificateProfileKind.ROOT_CA, selected.formatId());
        encoding().requireHybridContinuity(caId, selected, historical, profile, cancellation);
        KeyRef keyRef = replacementKey.orElse(root.issuerKeyRef());
        byte[] spki = keyRef.equals(generation.signingKeyRef()) ? issuerPublicKey.bytes() : encoding().publicKeyInfo(keyRef, cancellation);
        EncodedObject exactKey = new EncodedObject(Encoding.DER, spki);
        // RFC2253 reparsing can change ASN.1 string types and break exact issuer-name continuity.
        X500Principal subject = Pkix.parseCertificate(CredentialContent.materializeForBc(store, selected.content()))
                .getSubjectX500Principal();
        List<SubjectRdn> rdns = CaCertificateProfileValidator.validateTrustedSubject(subject, profile.definition());
        ValidatedCaCertificateRequest approved = CaCertificateProfileValidator.validateApprovedSubject(
                ValidatedCaCertificateRequest.Operation.CREATE_ROOT, profile, CertificateProfileKind.ROOT_CA,
                selected.formatId(), caId, caId, rdns, exactKey, requestedValidity, evaluationTime,
                Optional.empty(), serial, authority);
        return new ExistingRoot(selected, profile, keyRef, spki, subject, approved);
    }

    private record ExistingRoot(Credential selected, ActiveCertificateProfile profile, KeyRef keyRef, byte[] spki,
            X500Principal subject, ValidatedCaCertificateRequest approved) { }

    private CaOutgoingBinding outgoing(ActiveCertificateProfile profile,
            KeyRef primaryRef, Optional<KeyRef> alternativeOverride, byte[] primarySpki) throws IOException {
        return outgoing(primaryRef, alternativeOverride, primarySpki, profile.definition().hybridMode());
    }

    private CaOutgoingBinding outgoing(KeyRef primaryRef, Optional<KeyRef> alternativeOverride, byte[] primarySpki, HybridCertificateMode selectedMode) throws IOException {
        if (!(provider instanceof PublicKeyInfoSource keys)) { throw reject("PUBLIC_KEY_SOURCE_MISSING"); }
        IssuerKeyBinding primary = IssuerBindingResolver.createKey(primaryRef, signature, primarySpki,
                reference -> {
                    if (!primaryRef.equals(reference)) { throw reject("SUBJECT_KEY_REFERENCE_DIFFERS"); }
                    return new EncodedObject(Encoding.DER, primarySpki);
                }, authority);
        Optional<IssuerKeyBinding> alternative = Optional.empty();
        if (selectedMode instanceof HybridCertificateMode.AltSignature mode) {
            KeyRef reference = alternativeOverride.orElseGet(() -> new KeyRef(mode.altKeyRef()));
            alternative = Optional.of(IssuerBindingResolver.createKey(reference,
                    authority.resolveIdentity(mode.altSignatureAlgorithmId()), encoding().publicKeyInfo(reference, CancellationSignal.NONE), keys, authority));
        }
        return new CaOutgoingBinding(primary, alternative, bindings.commitment());
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

    // This custody boundary must classify or clean up every provider/runtime failure while preserving the established outcome.
    @SuppressWarnings({ "PMD.AvoidCatchingGenericException" })
    private DomainSigningRequest stage(AccessContext access, KeyRef keyRef, SigningSubmissionId submission,
            Duration ttl, DomainContinuationTemplate template, byte[] tbs, CancellationSignal cancellation) throws IOException {
        DurableContentReference content = null;
        try {
            cancellation.throwIfCancelled();
            try (ContentSink sink = store.stagedContent().beginContent(Encoding.DER, DurableContentReference.Lifecycle.OPERATION);
                    OutputStream output = sink.outputStream()) {
                int offset = 0;
                while (offset < tbs.length) {
                    cancellation.throwIfCancelled();
                    int count = Math.min(16 * 1024, tbs.length - offset);
                    output.write(tbs, offset, count);
                    offset += count;
                }
                cancellation.throwIfCancelled();
                content = sink.complete();
            }
            cancellation.throwIfCancelled();
            return new DomainSigningRequest(submission.id(), access, keyRef, signature.canonicalForm(),
                    Encoding.BINARY, content, ttl, template, Optional.empty());
        } catch (IOException | RuntimeException | Error primary) {
            if (content != null) {
                try { store.stagedContent().retireUnownedContent(content); }
                catch (IOException | RuntimeException cleanup) { primary.addSuppressed(cleanup); }
            }
            throw primary;
        }
    }

    private static PkiException reject(String code) { return new PkiException("Root creation rejected: code=" + code); }

    private RootCertificateEncoding encoding() {
        return new RootCertificateEncoding(store, provider, signature, authority, bindings);
    }
}
