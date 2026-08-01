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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialBundle;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.issuance.BundleCommand;
import zeroecho.pki.api.issuance.IssueEndEntityCommand;
import zeroecho.pki.api.issuance.ReissueCommand;
import zeroecho.pki.api.issuance.RenewCommand;
import zeroecho.pki.api.issuance.ReplaceCommand;
import zeroecho.pki.api.issuance.VerificationPolicy;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.request.CertificationRequest;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.request.ProofOfPossessionResult;
import zeroecho.pki.api.request.ProofOfPossessionStatus;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
import zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework;
import zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot;
import zeroecho.pki.impl.framework.x509.X509BuiltInDefaults;
import zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Default implementation of {@link IssuanceService}.
 *
 * <p>
 * This service coordinates end-entity credential issuance against the
 * configured {@link PkiStore} and delegates format-specific issuance work to
 * the active {@link CredentialFramework}. The store is used as the
 * authoritative source of issuer CA state and previously persisted credentials,
 * while the framework backend performs the actual credential construction for
 * the selected format.
 * </p>
 *
 * <p>
 * The implementation enforces these issuance-side invariants:
 * </p>
 * <ul>
 * <li>the issuer CA must exist,</li>
 * <li>the issuer CA must be in {@link CaState#ACTIVE} state,</li>
 * <li>the issuer CA must expose an effectively usable credential for the active
 * framework {@link FormatId},</li>
 * <li>the signed CSR is reparsed into bounded typed subject and SAN values and
 * validated against one exact active deny-by-default profile,</li>
 * <li>only a gate-produced {@link ValidatedCertificateRequest} crosses the
 * issuer-backend boundary,</li>
 * <li>the backend result is reparsed and its subject, SAN, public key, issuer,
 * serial, validity, BasicConstraints, KU, EKU, extension criticality, complete
 * extension set, and signature must match before persistence.</li>
 * </ul>
 *
 * <p>
 * Credential bundles returned by this service are assembled at runtime. Only
 * the newly issued leaf {@link Credential} is persisted by this implementation.
 * Certificate chain assembly, publication, and advanced bundle composition are
 * treated as higher-layer concerns.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>This service does not access private key material directly.</li>
 * <li>Issuer key usage is represented only through an opaque key reference
 * supplied by the trusted issuer selection boundary.</li>
 * <li>The correctness of issuance semantics depends on the configured
 * {@link CredentialFramework} matching the requested runtime format and on the
 * backend honoring the supplied issuer material.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * This class is stateless apart from its immutable collaborators. It is safe
 * for concurrent use provided that the configured {@link PkiStore} and
 * {@link CredentialFramework} implementations are safe for the intended
 * concurrency model.
 * </p>
 */
// PMD cannot infer that retaining boundary causes would violate the redaction contract.
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.PreserveStackTrace" })
public final class DefaultIssuanceService implements IssuanceService {

    /**
     * Maximum accepted encoded PKCS#10 request size (one mebibyte).
     */
    /* default */ static final int MAX_CSR_DER_BYTES = 1024 * 1024;

    private static final Principal SYSTEM_PKI = new Principal("SYSTEM", "pki");
    private static final Purpose ISSUANCE_PURPOSE = new Purpose("ISSUANCE");

    private final PkiStore store;
    private final CredentialFramework framework;
    private final CredentialIssuerBackend issuerBackend;
    private final AuditSink auditSink;
    private final EffectiveCredentialStatusResolver statusResolver;
    private final ProfileService profileService;
    private final Clock clock;
    private final X509AuthoritySnapshot authority;
    private final zeroecho.core.spec.AlgorithmIdentity expectedSignature;

    /**
     * Creates the issuance service bound to the supplied persistence and framework
     * collaborators.
     *
     * @param store          PKI store used for issuer CA lookup and credential
     *                       persistence; must not be {@code null}
     * @param framework      credential framework providing format-specific issuance
     *                       parsing and proof verification; must not be
     *                       {@code null}
     * @param issuerBackend  privileged issuer implementation that accepts only
     *                       gate-produced candidates; must not be {@code null}
     * @param auditSink      required sink for safe rejection audit events; must not
     *                       be {@code null}
     * @param statusResolver authoritative runtime credential-status resolver; must
     *                       not be {@code null}
     * @throws NullPointerException if an argument is {@code null}
     */
    public DefaultIssuanceService(PkiStore store, CredentialFramework framework, CredentialIssuerBackend issuerBackend,
            AuditSink auditSink, EffectiveCredentialStatusResolver statusResolver, ProfileService profileService,
            Clock clock) {
        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
        this.issuerBackend = Objects.requireNonNull(issuerBackend, "issuerBackend");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.statusResolver = Objects.requireNonNull(statusResolver, "statusResolver");
        this.profileService = Objects.requireNonNull(profileService, "profileService");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (!(framework instanceof BcX509CredentialFramework x509Framework)) {
            throw new IllegalArgumentException("X.509 issuance requires an algorithm authority");
        }
        this.authority = x509Framework.authority();
        this.expectedSignature = authority.resolveDefault(X509BuiltInDefaults.PKI_SIGNATURE_DEFAULT_V1).signature();
    }

    /**
     * Issues a new end-entity credential and returns the resulting runtime bundle.
     *
     * <p>
     * The issuer CA is resolved from the store and validated as active before
     * issuance proceeds. The method then selects a suitable issuer credential for
     * the active framework format, enriches the supplied issuance overrides with
     * issuer material required by the X.509 backend wiring, delegates issuance to
     * the framework backend, defensively snapshots and validates the result, and
     * persists only the validated leaf credential.
     * </p>
     *
     * <p>
     * The returned {@link CredentialBundle} may contain additional runtime material
     * such as chain elements, but this implementation persists only
     * {@link CredentialBundle#credential()}.
     * </p>
     *
     * @param command end-entity issuance command; must not be {@code null}
     * @return defensive snapshot of the validated credential bundle
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the issuer CA does not exist, is not active,
     *                              has no credentials, no compatible effectively
     *                              usable issuer credential can be selected, or
     *                              current revocation state cannot be resolved,
     *                              issuer material enrichment fails, backend
     *                              issuance or result validation fails, or
     *                              persistence of the validated leaf fails
     */
    @Override
    public CredentialBundle issueEndEntity(IssueEndEntityCommand command) {
        Objects.requireNonNull(command, "command");
        CaRecord issuer = store.getCa(command.issuerCaId()).orElseThrow(() -> new PkiException("Issuer CA not found"));

        if (issuer.state() != CaState.ACTIVE) {
            throw new PkiException("Issuer CA not ACTIVE");
        }
        if (issuer.caCredentials().isEmpty()) {
            throw new PkiException("Issuer CA has no credentials");
        }

        VerifiedIssuanceCandidate candidate = verifyIssuanceCandidate(command);
        ActiveCertificateProfile active;
        try {
            active = profileService.requireActiveProfile(command.profileId());
        } catch (PkiException failure) {
            throw rejection(candidate.request(), "PROFILE_NOT_ACTIVE");
        }
        CertificateProfile profile = active.profile();
        if (!command.profileId().equals(active.reference().profileId())) {
            throw rejection(candidate.request(), "PROFILE_ID_MISMATCH");
        }
        if (!framework.formatId().equals(profile.formatId())
                || !candidate.request().formatId().equals(profile.formatId())) {
            throw rejection(candidate.request(), "PROFILE_FORMAT_MISMATCH");
        }
        Instant evaluationTime = clock.instant();
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCred = CredentialSnapshots.copy(selectIssuerCredential(issuer, framework.formatId(),
                CredentialUse.END_ENTITY_ISSUER, statusEvaluation));
        ValidatedCertificateRequest validated;
        try {
            validated = CertificateProfileValidator.validate(candidate, profile, active.reference(), issuerCred,
                    evaluationTime, authority);
        } catch (PkiException exception) {
            throw rejection(candidate.request(), statusCode(exception));
        }
        BigInteger serial = CertificateSerialAllocator.allocate();

        CredentialBundle bundle;
        try {
            bundle = CredentialSnapshots
                    .copy(issuerBackend.issueEndEntity(validated, issuerCred.content(), issuer.issuerKeyRef(), serial));
        } catch (RuntimeException ex) { // NOPMD - framework output must cross the snapshot boundary
            throw rejection(candidate.request(), "BACKEND_CREDENTIAL_MISMATCH");
        }
        requireIssuedCredentialMatches(validated, issuerCred, serial, bundle, candidate.request());
        store.putCredential(bundle.credential());
        return bundle;
    }

    /**
     * Selects the issuer credential that should be used for issuance in the given
     * format.
     *
     * <p>
     * The selected credential must match the requested {@link FormatId} and resolve
     * as effectively usable against current revocation state and the operation's
     * captured evaluation instant. Resolution failures abort selection.
     * </p>
     *
     * @param issuer   issuer CA record containing candidate credentials; must not
     *                 be {@code null}
     * @param formatId format identifier required by the active framework; must not
     *                 be {@code null}
     * @return selected issuer credential
     * @throws NullPointerException if {@code issuer} or {@code formatId} is
     *                              {@code null}
     * @throws PkiException         if the issuer CA has no compatible effectively
     *                              usable credential or revocation resolution fails
     */
    private Credential selectIssuerCredential(CaRecord issuer, FormatId formatId, CredentialUse use,
            EffectiveCredentialStatusResolver.Evaluation evaluation) {
        Objects.requireNonNull(issuer, "issuer");
        Objects.requireNonNull(formatId, "formatId");

        Credential lastRejected = null;
        EffectiveCredentialStatus lastStatus = null;
        for (Credential c : issuer.caCredentials()) {
            if (c == null || !formatId.equals(c.formatId())) {
                continue;
            }
            EffectiveCredentialStatus status;
            try {
                status = evaluation.resolve(c);
            } catch (PkiException exception) {
                CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), c, use,
                        StoreBackedEffectiveCredentialStatusResolver.RESOLUTION_FAILED_CODE, null);
                throw exception;
            }
            if (status == EffectiveCredentialStatus.USABLE) {
                return c;
            }
            lastRejected = c;
            lastStatus = status;
        }
        if (lastRejected != null) {
            CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), lastRejected, use,
                    "ISSUER_CREDENTIAL_UNAVAILABLE", lastStatus);
        }
        throw new PkiException("Issuer credential unavailable: code=ISSUER_CREDENTIAL_UNAVAILABLE");
    }

    private VerifiedIssuanceCandidate verifyIssuanceCandidate(IssueEndEntityCommand command) {
        ParsedCertificationRequest supplied = command.request();
        byte[] csrDer = extractCsrDer(supplied);
        try {
            ParsedCertificationRequest reparsed = reparse(supplied, csrDer);
            requireExactMatch(supplied, reparsed);
            ProofOfPossessionStatus proofKind = requireVerifiedProof(supplied, reparsed);
            return new VerifiedIssuanceCandidate(reparsed, reparsed.requestId(), reparsed.publicKeyInfo(), proofKind,
                    command);
        } finally {
            java.util.Arrays.fill(csrDer, (byte) 0);
        }
    }

    private byte[] extractCsrDer(ParsedCertificationRequest supplied) {
        Optional<AttributeValue> value;
        try {
            value = supplied.attributes().get(BcX509Attributes.CSR_DER);
        } catch (RuntimeException ex) { // NOPMD - untrusted AttributeSet implementations fail closed
            throw rejection(supplied, "CSR_MALFORMED");
        }
        if (value.isEmpty()) {
            throw rejection(supplied, "CSR_MISSING");
        }
        AttributeValue csrValue = value.get();
        if (!(csrValue instanceof AttributeValue.BytesValue bytesValue)) {
            throw rejection(supplied, "CSR_MALFORMED");
        }
        byte[] encoded = bytesValue.value();
        if (encoded.length > MAX_CSR_DER_BYTES) {
            throw rejection(supplied, "CSR_TOO_LARGE");
        }
        return encoded.clone();
    }

    private ParsedCertificationRequest reparse(ParsedCertificationRequest supplied, byte[] csrDer) {
        if (!framework.formatId().equals(supplied.formatId())) {
            throw rejection(supplied, "FORMAT_UNSUPPORTED");
        }
        try {
            CertificationRequest diagnostic = new CertificationRequest(supplied.formatId(),
                    new EncodedObject(Encoding.DER, csrDer));
            return framework.requestParser().parse(diagnostic);
        } catch (RuntimeException ex) { // NOPMD - framework parsing of hostile input fails closed
            throw rejection(supplied, "CSR_MALFORMED");
        }
    }

    private void requireExactMatch(ParsedCertificationRequest supplied, ParsedCertificationRequest reparsed) {
        if (!supplied.formatId().equals(reparsed.formatId())) {
            throw rejection(supplied, "FORMAT_MISMATCH");
        }
        if (!supplied.requestId().equals(reparsed.requestId())) {
            throw rejection(supplied, "REQUEST_ID_MISMATCH");
        }
        if (!supplied.subjectRef().equals(reparsed.subjectRef())) {
            throw rejection(supplied, "SUBJECT_MISMATCH");
        }
        if (!supplied.subjectRdns().equals(reparsed.subjectRdns())
                || !supplied.subjectAlternativeNames().equals(reparsed.subjectAlternativeNames())
                || supplied.subjectAlternativeNamePresent() != reparsed.subjectAlternativeNamePresent()
                || !supplied.requestedValidity().equals(reparsed.requestedValidity())
                || !supplied.requestedProfileId().equals(reparsed.requestedProfileId())
                || supplied.attributes().ids().size() != 1
                || supplied.attributes().getAll(BcX509Attributes.CSR_DER).size() != 1) {
            throw rejection(supplied, "REQUEST_SEMANTICS_MISMATCH");
        }
        byte[] suppliedSpki = supplied.publicKeyInfo().bytes();
        byte[] reparsedSpki = reparsed.publicKeyInfo().bytes();
        try {
            if (supplied.publicKeyInfo().encoding() != Encoding.DER
                    || reparsed.publicKeyInfo().encoding() != Encoding.DER
                    || !MessageDigest.isEqual(suppliedSpki, reparsedSpki)) {
                throw rejection(supplied, "SPKI_MISMATCH");
            }
        } finally {
            java.util.Arrays.fill(suppliedSpki, (byte) 0);
            java.util.Arrays.fill(reparsedSpki, (byte) 0);
        }
    }

    private ProofOfPossessionStatus requireVerifiedProof(ParsedCertificationRequest supplied,
            ParsedCertificationRequest reparsed) {
        ParsedCertificationRequest verificationRequest = VerifiedIssuanceCandidate.snapshot(reparsed);
        ProofOfPossessionResult proof;
        try {
            proof = framework.proofOfPossessionVerifier().verify(verificationRequest,
                    new VerificationPolicy(true, Optional.empty()));
        } catch (RuntimeException ex) { // NOPMD - verifier boundary failures reject issuance
            throw rejection(supplied, "PROOF_FAILED");
        }
        if (proof == null) {
            throw rejection(supplied, "PROOF_FAILED");
        }
        if (proof.status() != ProofOfPossessionStatus.VERIFIED) {
            throw rejection(supplied, proofCode(proof.status()));
        }

        return proof.status();
    }

    private PkiException rejection(ParsedCertificationRequest request, String code) {
        PkiException rejection = new PkiException("End-entity issuance rejected: " + code);
        try {
            auditSink.record(new AuditEvent(clock.instant(), "ISSUANCE", "ISSUE_END_ENTITY_REJECTED", SYSTEM_PKI,
                    ISSUANCE_PURPOSE, Optional.empty(), Optional.of(request.formatId()), Map.of("code", code)));
        } catch (RuntimeException auditFailure) { // NOPMD - preserve stable rejection and fail closed
            // Best-effort auditing must not expose listener-controlled diagnostics.
        }
        return rejection;
    }

    private void requireIssuedCredentialMatches(ValidatedCertificateRequest validated, Credential issuerCredential,
            BigInteger allocatedSerial, CredentialBundle bundle, ParsedCertificationRequest auditRequest) {
        if (bundle == null || bundle.credential() == null) {
            throw rejection(auditRequest, "BACKEND_CREDENTIAL_MISMATCH");
        }
        Credential credential = bundle.credential();
        try {
            CredentialProfileBindings.requireEndEntityBinding(credential.profileBinding(),
                    validated.profileReference());
            if (!framework.formatId().equals(credential.formatId()) || credential.content().encoding() != Encoding.DER
                    || !credential.subjectRef().equals(validated.subjectRef())
                    || !credential.issuerRef().equals(new zeroecho.pki.api.IssuerRef(validated.issuerCaId()))
                    || credential.status() != CredentialStatus.ISSUED) {
                throw rejection(auditRequest, "BACKEND_CREDENTIAL_MISMATCH");
            }
            CredentialContent.validateCertificate(store, credential.content(), authority,
                    Optional.of(expectedSignature));
            CredentialContent.validateCertificate(store, issuerCredential.content(), authority, Optional.empty());
            byte[] credentialDer = CredentialContent.materializeForBc(store, credential.content());
            X509CertificateHolder holder = new X509CertificateHolder(credentialDer);
            X509CertificateHolder issuerHolder = new X509CertificateHolder(
                    CredentialContent.materializeForBc(store, issuerCredential.content()));
            byte[] actualSpki = holder.getSubjectPublicKeyInfo().getEncoded();
            if (!MessageDigest.isEqual(validated.exactPublicKey().bytes(), actualSpki)
                    || !holder.getSubject().equals(BcX509ProfileSupport.subject(validated.subjectRdns()))
                    || !holder.getIssuer().equals(issuerHolder.getSubject())
                    || !holder.isSignatureValid(
                            new JcaContentVerifierProviderBuilder().build(issuerHolder.getSubjectPublicKeyInfo()))
                    || !holder.getSerialNumber().equals(allocatedSerial)
                    || !credential.publicKeyId().equals(new PkiId("spki:" + sha256Hex(actualSpki)))
                    || !credential.credentialId().equals(new PkiId("x509:" + sha256Hex(credentialDer)))
                    || !credential.serialOrUniqueId().equals(holder.getSerialNumber().toString())
                    || !credential.validity().equals(validated.validity())
                    || validated.validity().notBefore().getEpochSecond() != holder.getNotBefore().toInstant()
                            .getEpochSecond()
                    || validated.validity().notAfter().getEpochSecond() != holder.getNotAfter().toInstant()
                            .getEpochSecond()
                    || !BcX509ProfileSupport.matchesLeafExtensions(holder, validated)) {
                throw rejection(auditRequest, "BACKEND_CREDENTIAL_MISMATCH");
            }
        } catch (CredentialProfileBindings.Mismatch mismatch) {
            throw rejection(auditRequest, CredentialProfileBindings.MISMATCH_CODE);
        } catch (PkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw rejection(auditRequest, "BACKEND_CREDENTIAL_MISMATCH");
        }
    }

    private static String statusCode(PkiException exception) {
        String message = exception.getMessage();
        int codeIndex = message == null ? -1 : message.indexOf("code=");
        return codeIndex < 0 ? "PROFILE_VALIDATION_FAILED" : message.substring(codeIndex + 5);
    }

    private static String sha256Hex(byte[] input) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(input));
        } catch (java.security.NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }

    private static String proofCode(ProofOfPossessionStatus status) {
        return switch (status) {
            case FAILED -> "PROOF_FAILED";
            case NOT_PRESENT -> "PROOF_NOT_PRESENT";
            case NOT_SUPPORTED -> "PROOF_NOT_SUPPORTED";
            case VERIFIED -> throw new IllegalArgumentException("VERIFIED is not a rejection status");
        };
    }

    /**
     * Requests credential renewal.
     *
     * <p>
     * The {@link IssuanceService} contract exposes this operation, but the current
     * runtime build does not implement it.
     * </p>
     *
     * @param command renewal request; must not be {@code null}
     * @return never returns normally
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         always, because renewal is not implemented in
     *                              this runtime build
     */
    @Override
    public CredentialBundle renew(RenewCommand command) {
        Objects.requireNonNull(command, "command");
        throw new PkiException("Renew is not implemented in this runtime build");
    }

    /**
     * Requests credential replacement.
     *
     * <p>
     * The {@link IssuanceService} contract exposes this operation, but the current
     * runtime build does not implement it.
     * </p>
     *
     * @param command replacement request; must not be {@code null}
     * @return never returns normally
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         always, because replacement is not implemented
     *                              in this runtime build
     */
    @Override
    public CredentialBundle replace(ReplaceCommand command) {
        Objects.requireNonNull(command, "command");
        throw new PkiException("Replace is not implemented in this runtime build");
    }

    /**
     * Requests credential reissuance.
     *
     * <p>
     * The {@link IssuanceService} contract exposes this operation, but the current
     * runtime build does not implement it.
     * </p>
     *
     * @param command reissuance request; must not be {@code null}
     * @return never returns normally
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         always, because reissuance is not implemented in
     *                              this runtime build
     */
    @Override
    public CredentialBundle reissue(ReissueCommand command) {
        Objects.requireNonNull(command, "command");
        throw new PkiException("Reissue is not implemented in this runtime build");
    }

    /**
     * Builds a runtime credential bundle for a previously persisted leaf
     * credential.
     *
     * <p>
     * This implementation currently returns a minimal bundle containing only the
     * resolved leaf credential and an empty chain. Chain discovery, issuer path
     * construction, and publication-aware bundle assembly are intentionally left to
     * higher layers.
     * </p>
     *
     * @param command bundle construction command identifying the leaf credential;
     *                must not be {@code null}
     * @return minimal credential bundle containing the resolved leaf credential and
     *         no chain elements
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the requested credential does not exist in
     *                              the store or is not currently usable
     */
    @Override
    public CredentialBundle buildBundle(BundleCommand command) {
        Objects.requireNonNull(command, "command");
        PkiId credId = command.credentialId();
        Credential leaf = store.getCredential(credId).orElseThrow(() -> new PkiException("Credential not found"));
        EffectiveCredentialStatusResolver.Evaluation evaluation = statusResolver.beginEvaluation();
        EffectiveCredentialStatus status;
        try {
            status = evaluation.resolve(leaf);
        } catch (PkiException exception) {
            CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), leaf, CredentialUse.BUNDLE_DELIVERY,
                    StoreBackedEffectiveCredentialStatusResolver.RESOLUTION_FAILED_CODE, null);
            throw exception;
        }
        if (status != EffectiveCredentialStatus.USABLE) {
            CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), leaf, CredentialUse.BUNDLE_DELIVERY,
                    StoreBackedEffectiveCredentialStatusResolver.NOT_USABLE_CODE, status);
            throw new PkiException(
                    "Credential trust rejected: code=" + StoreBackedEffectiveCredentialStatusResolver.NOT_USABLE_CODE);
        }
        // Minimal bundle: leaf only. Chain selection and publication are higher-layer
        // concerns.
        return new CredentialBundle(leaf, List.of());
    }
}
