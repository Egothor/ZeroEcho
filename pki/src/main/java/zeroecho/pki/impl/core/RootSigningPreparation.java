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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability.Direction;
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
import zeroecho.pki.impl.hybrid.AltSignatureExtensions;
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
import zeroecho.pki.api.profile.X509AlgorithmBindingPolicy;
import zeroecho.pki.api.request.SubjectRdn;
import zeroecho.pki.impl.core.continuation.DomainCommandEncoding;
import zeroecho.pki.impl.core.continuation.DomainContinuationTemplate;
import zeroecho.pki.impl.core.continuation.DomainSigningRequest;
import zeroecho.pki.impl.core.continuation.FullCrlSigningCommand;
import zeroecho.pki.impl.core.continuation.ManagedKeyProofCommand;
import zeroecho.pki.impl.framework.x509.StreamingDerReader;
import zeroecho.pki.impl.framework.x509.X509AlgorithmRole;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.X509SecurityFloor;
import zeroecho.pki.impl.framework.x509.X509SuiteCompatibility;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.spi.crypto.PublicKeyInfoSource;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.ContentSink;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
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
     * @param pureEdDsaMaximum inclusive positive pure-EdDSA input bound in bytes
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
     * Freezes the exact active root profile, approved subject and one provider SPKI
     * into a single unsigned certificate candidate. Whole-second validity narrows
     * the approved interval. All policy, algorithm and size checks precede staging.
     * A successful return transfers one unowned candidate to the caller, which must
     * adopt or retire it; the access context is preserved without granting authority.
     * @param access separately authenticated and authorized invocation context
     * @param input immutable root creation command with an existing managed key
     * @param submission fresh internally allocated submission identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged root signing request
     * @throws IOException if DER validation, staging or cancellation fails
     * @throws RuntimeException if profile, subject, provider, key, binding or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, CaCreateCommand input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(input, "input");
        Objects.requireNonNull(submission, "submission");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        validateSubmission(submission, ttl);
        Instant evaluationTime = clock.instant();
        ActiveCertificateProfile profile = store.requireActiveProfile(input.profileId());
        if (!profile.reference().profileId().equals(input.profileId())
                || !input.formatId().equals(BcX509CredentialFramework.FORMAT_ID)) { throw reject("PROFILE_BINDING_INVALID"); }
        CaCertificateProfileValidator.requireProfileShape(profile, CertificateProfileKind.ROOT_CA, input.formatId());
        if (!input.attributes().ids().isEmpty()) { throw reject("ATTRIBUTES_NOT_SUPPORTED"); }
        byte[] spki = publicKeyInfo(input.keyRef(), cancellation);
        EncodedObject exactKey = new EncodedObject(Encoding.DER, spki);
        PkiId root = DomainCommandEncoding.rootAuthorityId(submission.id());
        BigInteger serial = CertificateSerialAllocator.allocate();
        ValidatedCaCertificateRequest approved = CaCertificateProfileValidator.validate(
                ValidatedCaCertificateRequest.Operation.CREATE_ROOT, profile, CertificateProfileKind.ROOT_CA,
                input.formatId(), root, root, input.subjectRef(), exactKey, Optional.empty(), evaluationTime,
                Optional.empty(), serial, authority);
        Validity validity = wholeSecondValidity(approved.validity());
        AlgorithmIdentifier algorithm = algorithm(approved);
        X500Principal subject = BcX509ProfileSupport.subject(approved.subjectRdns());
        byte[] tbs = buildTbs(input.altKeyRef(), profile.definition().hybridMode(), approved, algorithm, subject, spki,
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
                approved.policy().toString(), approved.algorithmBindingPolicy().toString(), root.value());
        return stage(access, input.keyRef(), submission, ttl, template, tbs, cancellation);
    }

    /**
     * Prepares root rollover using the authoritative current key and the active
     * version of the selected credential's profile. The old credential supplies
     * profile identity only; its expiry/revocation does not cap or veto renewal.
     * This internal root-typed primitive does not provide a public lifecycle dispatcher.
     * @param access separately authorized invocation context
     * @param input root identifier and optional policy-checked validity
     * @param submission fresh internally allocated submission identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged request requiring adoption or retirement
     * @throws IOException if DER validation, staging or cancellation fails
     * @throws RuntimeException if authority, profile, key, bindings or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, CaRolloverCommand.Root input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(input, "input");
        return prepareExisting(access, input.caId(), Optional.empty(), input.requestedValidity(), input.attributes(),
                submission, ttl, cancellation);
    }

    /**
     * Prepares root rotation with the supplied managed key and authoritative active
     * profile. Reusing the current key reference is permitted. The fresh candidate
     * must subsequently obtain a valid self-signature against its frozen public key.
     * No old-key proof, chain walk, primary-signing dispatch or CA mutation is performed.
     * An AltSignature root retains its alternative key and signs a fresh pre-TBS.
     * @param access separately authorized invocation context
     * @param input root identifier and explicitly provisioned replacement key
     * @param submission fresh internally allocated submission identity
     * @param ttl positive configured signing lifetime
     * @param cancellation cooperative pre-acceptance cancellation
     * @return caller-owned staged request requiring adoption or retirement
     * @throws IOException if DER validation, staging or cancellation fails
     * @throws RuntimeException if authority, profile, key, bindings or bounds are invalid
     */
    public DomainSigningRequest prepare(AccessContext access, CaKeyRotationCommand.Root input,
            SigningSubmissionId submission, Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(input, "input");
        return prepareExisting(access, input.caId(), Optional.of(input.newKeyRef()), Optional.empty(), input.attributes(),
                submission, ttl, cancellation);
    }

    private DomainSigningRequest prepareExisting(AccessContext access, PkiId caId, Optional<KeyRef> replacementKey,
            Optional<Validity> requestedValidity, AttributeSet attributes, SigningSubmissionId submission,
            Duration ttl, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(access, "access");
        Objects.requireNonNull(submission, "submission");
        Objects.requireNonNull(ttl, "ttl");
        Objects.requireNonNull(cancellation, "cancellation").throwIfCancelled();
        validateSubmission(submission, ttl);
        if (!attributes.ids().isEmpty()) { throw reject("ATTRIBUTES_NOT_SUPPORTED"); }
        Instant evaluationTime = clock.instant();
        CaRecord root = store.getCa(caId).orElseThrow(() -> reject("ROOT_MISSING"));
        if (!root.caId().equals(caId) || root.kind() != CaKind.ROOT || root.state() != CaState.ACTIVE) {
            throw reject("ROOT_UNAVAILABLE");
        }
        Credential selected = IssuerAuthorities.currentCredential(store, root);
        if (!(selected.profileBinding() instanceof CaProfileBinding historical)) { throw reject("ROOT_PROFILE_BINDING_INVALID"); }
        ActiveCertificateProfile profile = store.requireActiveProfile(historical.reference().profileId());
        if (!profile.reference().profileId().equals(historical.reference().profileId())
                || !selected.formatId().equals(BcX509CredentialFramework.FORMAT_ID)) { throw reject("PROFILE_BINDING_INVALID"); }
        CaCertificateProfileValidator.requireProfileShape(profile, CertificateProfileKind.ROOT_CA, selected.formatId());
        requireHybridContinuity(selected, historical, profile, cancellation);
        KeyRef keyRef = replacementKey.orElse(root.issuerKeyRef());
        byte[] spki = publicKeyInfo(keyRef, cancellation);
        EncodedObject exactKey = new EncodedObject(Encoding.DER, spki);
        X500Principal subject = new X500Principal(root.subjectRef().value());
        List<SubjectRdn> rdns = CaCertificateProfileValidator.validateTrustedSubject(subject, profile.definition());
        BigInteger serial = CertificateSerialAllocator.allocate();
        ValidatedCaCertificateRequest approved = CaCertificateProfileValidator.validateApprovedSubject(
                ValidatedCaCertificateRequest.Operation.CREATE_ROOT, profile, CertificateProfileKind.ROOT_CA,
                selected.formatId(), caId, caId, rdns, exactKey, requestedValidity, evaluationTime,
                Optional.empty(), serial, authority);
        Validity validity = wholeSecondValidity(approved.validity());
        AlgorithmIdentifier algorithm = algorithm(approved);
        byte[] tbs = buildTbs(Optional.empty(), profile.definition().hybridMode(), approved, algorithm, subject,
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
                approved.policy().toString(), approved.algorithmBindingPolicy().toString(), caId.value());
        return stage(access, keyRef, submission, ttl, template, tbs, cancellation);
    }


    private byte[] buildTbs(Optional<KeyRef> alternativeKey, HybridCertificateMode hybridMode,
            ValidatedCaCertificateRequest approved,
            AlgorithmIdentifier algorithm, X500Principal subject, byte[] spki, Validity validity,
            CancellationSignal cancellation) throws IOException {
        if (!(hybridMode instanceof HybridCertificateMode.AltSignature altSig)) {
            return Pkix.certificateBuilder()
                    .serialNumber(approved.serial()).issuer(subject).subject(subject).publicKeyInfo(spki)
                    .validity(validity.notBefore(), validity.notAfter())
                    .basicConstraints(BasicConstraints.ca(approved.policy().pathLengthConstraint()),
                            approved.policy().basicConstraintsCritical())
                    .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                            approved.policy().keyUsageCritical())
                    .buildTbs(algorithm);
        }
        // Hybrid: AltSignature mode — build pre-TBS, sign with alt key, build final TBS.
        KeyRef altKeyRef = alternativeKey.orElseGet(() -> new KeyRef(altSig.altKeyRef()));
        byte[] altSpki = publicKeyInfo(altKeyRef, cancellation);
        AlgorithmIdentity altIdentity = authority.resolveIdentity(altSig.altSignatureAlgorithmId());
        if (altIdentity.kind() != AlgorithmIdentity.Kind.SIGNATURE) { throw reject("ALT_ALGORITHM_INVALID"); }
        X509SecurityFloor.requirePermitted(altIdentity);
        X509AlgorithmBinding altSigBinding = bindings.standard(altIdentity,
                X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE)
                .orElseThrow(() -> reject("ALT_ALGORITHM_BINDING_MISSING"));
        AlgorithmIdentifier altAlgId = toAltAlgorithmIdentifier(altSigBinding);
        byte[] preTbs = Pkix.certificateBuilder()
                .serialNumber(approved.serial()).issuer(subject).subject(subject).publicKeyInfo(spki)
                .validity(validity.notBefore(), validity.notAfter())
                .basicConstraints(BasicConstraints.ca(approved.policy().pathLengthConstraint()),
                        approved.policy().basicConstraintsCritical())
                .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                        approved.policy().keyUsageCritical())
                .addExtension(AltSignatureExtensions.subjectAltPublicKeyInfo(altSpki))
                .addExtension(AltSignatureExtensions.altSignatureAlgorithm(altAlgId))
                .buildAlternativeSignatureTbs();
        if (preTbs.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) { throw reject("TBS_TOO_LARGE"); }
        if (!(provider instanceof AltSigningCapability altSigner)) { throw reject("ALT_SIGNING_CAPABILITY_UNAVAILABLE"); }
        cancellation.throwIfCancelled();
        byte[] altSignatureBytes;
        try {
            altSignatureBytes = altSigner.sign(altKeyRef, altSig.altSignatureAlgorithmId(), preTbs);
        } catch (GeneralSecurityException e) {
            throw new PkiException("Alt signature failed: code=ALT_SIGNING_FAILED", e);
        }
        if (altSignatureBytes == null || altSignatureBytes.length == 0
                || altSignatureBytes.length > CredentialContent.MAXIMUM_CERTIFICATE_BYTES) { throw reject("ALT_SIGNATURE_INVALID"); }
        zeroecho.pkix.sign.ContentVerifier verifier = Pkix.verifier(altSpki, altAlgId);
        try (OutputStream output = verifier.contentStream()) { output.write(preTbs); }
        if (!verifier.verify(altSignatureBytes)) { throw reject("ALT_SIGNATURE_INVALID"); }
        return Pkix.certificateBuilder()
                .serialNumber(approved.serial()).issuer(subject).subject(subject).publicKeyInfo(spki)
                .validity(validity.notBefore(), validity.notAfter())
                .basicConstraints(BasicConstraints.ca(approved.policy().pathLengthConstraint()),
                        approved.policy().basicConstraintsCritical())
                .keyUsage(Set.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                        approved.policy().keyUsageCritical())
                .addExtension(AltSignatureExtensions.subjectAltPublicKeyInfo(altSpki))
                .addExtension(AltSignatureExtensions.altSignatureAlgorithm(altAlgId))
                .addExtension(AltSignatureExtensions.altSignatureValue(altSignatureBytes))
                .buildTbs(algorithm);
    }

    private void requireHybridContinuity(Credential selected, CaProfileBinding historical,
            ActiveCertificateProfile active, CancellationSignal cancellation) throws IOException {
        zeroecho.pki.api.profile.ImportedCertificateProfileVersion previous = store.getProfileVersion(
                historical.reference().profileId(), historical.reference().profileVersion())
                .orElseThrow(() -> reject("ROOT_PROFILE_MISSING"));
        if (!previous.reference().equals(historical.reference())) { throw reject("ROOT_PROFILE_BINDING_INVALID"); }
        HybridCertificateMode oldMode = previous.definition().hybridMode();
        HybridCertificateMode newMode = active.definition().hybridMode();
        if (!oldMode.getClass().equals(newMode.getClass())) { throw reject("HYBRID_MODE_CHANGE_UNSUPPORTED"); }
        if (newMode instanceof HybridCertificateMode.AltSignature alternative) {
            byte[] encoded = CredentialContent.materializeForBc(store, selected.content());
            java.security.cert.X509Certificate certificate = Pkix.parseCertificate(encoded);
            byte[] expected = AltSignatureExtensions.requiredValue(certificate,
                    AltSignatureExtensions.OID_SUBJECT_ALT_PUBLIC_KEY_INFO);
            byte[] configured = publicKeyInfo(new KeyRef(alternative.altKeyRef()), cancellation);
            AlgorithmIdentifier algorithm = toAltAlgorithmIdentifier(bindings.standard(
                    authority.resolveIdentity(alternative.altSignatureAlgorithmId()),
                    X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE)
                    .orElseThrow(() -> reject("ALT_ALGORITHM_BINDING_MISSING")));
            if (!java.util.Arrays.equals(expected, configured)
                    || !java.util.Arrays.equals(Pkix.encodeAlgorithmIdentifier(algorithm),
                            AltSignatureExtensions.requiredValue(certificate,
                                    AltSignatureExtensions.OID_ALT_SIGNATURE_ALGORITHM))
                    || !Pkix.verifyAlternativeSignature(certificate, Pkix.publicKeyFromSubjectPublicKeyInfo(expected))) {
                throw reject("ALT_KEY_CONTINUITY_INVALID");
            }
        }
    }

    private static AlgorithmIdentifier toAltAlgorithmIdentifier(X509AlgorithmBinding binding) {
        return switch (binding.parameterRule()) {
            case ABSENT -> AlgorithmIdentifier.absent(binding.oid());
            case DER_NULL -> AlgorithmIdentifier.derNull(binding.oid());
            case STRUCTURED_DER -> throw reject("ALT_ALGORITHM_PARAMETER_RULE_UNSUPPORTED");
        };
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

    private byte[] publicKeyInfo(KeyRef keyRef, CancellationSignal cancellation) throws IOException {
        if (!(provider instanceof PublicKeyInfoSource source)
                || !provider.supportedAlgorithms().contains(signature.canonicalForm())) { throw reject("PUBLIC_KEY_SOURCE_UNAVAILABLE"); }
        cancellation.throwIfCancelled();
        EncodedObject exported = Objects.requireNonNull(source.resolvePublicKeyInfo(keyRef), "publicKeyInfo");
        cancellation.throwIfCancelled();
        if (exported.encoding() != Encoding.DER || exported.byteLength() < 1
                || exported.byteLength() > ManagedKeyProofCommand.MAX_SPKI_BYTES) { throw reject("PUBLIC_KEY_ENCODING_INVALID"); }
        byte[] spki = exported.bytes();
        new StreamingDerReader().validateSubjectPublicKeyInfo(spki, ManagedKeyProofCommand.MAX_SPKI_BYTES);
        return spki;
    }

    private AlgorithmIdentifier algorithm(ValidatedCaCertificateRequest request) {
        BcX509AlgorithmAdapter adapter = new BcX509AlgorithmAdapter(authority.bindings());
        AlgorithmIdentifier subjectAlgorithm = Pkix.subjectPublicKeyAlgorithm(request.exactPublicKey().bytes());
        AlgorithmIdentity subjectKey = adapter.decode(subjectAlgorithm, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM);
        X509SuiteCompatibility.requireCompatible(signature, subjectKey);
        X509AlgorithmBindingPolicy policy = request.algorithmBindingPolicy();
        X509AlgorithmBinding signingBinding = binding(signature, X509AlgorithmBinding.Role.CERTIFICATE_SIGNATURE,
                policy.certificateSignature());
        X509ExecutionPlan<SigningProvider> plan = authority.plan(signature, subjectKey, Direction.SIGN, Optional.empty(),
                "explicit", signingBinding.bindingId(), SigningProvider.class);
        authority.authorize(plan, provider, Direction.SIGN);
        X509AlgorithmBinding subjectBinding = binding(subjectKey, X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY, policy.subjectPublicKey());
        AlgorithmIdentifier expected = BcX509AlgorithmAdapter.toLib(authority.bindings().resolve(subjectBinding.bindingId(),
                subjectKey, X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM));
        if (!subjectAlgorithm.equals(expected)) { throw reject("SUBJECT_BINDING_DIFFERS"); }
        return BcX509AlgorithmAdapter.toLib(plan.selection().binding());
    }

    private X509AlgorithmBinding binding(AlgorithmIdentity identity, X509AlgorithmBinding.Role role,
            Optional<X509AlgorithmBindingPolicy.BindingReference> reference) {
        X509AlgorithmBinding selected = reference.map(value -> bindings.require(value.bindingId(), value.semanticCommitment()))
                .orElseGet(() -> bindings.standard(identity, role).orElseThrow(() -> reject("BINDING_MISSING")));
        if (selected.role() != role || !selected.algorithmIdentity().equals(identity)
                || reference.isPresent() && selected.origin() == X509AlgorithmBinding.Origin.STANDARD) { throw reject("BINDING_DIFFERS"); }
        return selected;
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
}
