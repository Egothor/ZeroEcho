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
import java.math.BigInteger;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaImportCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaQuery;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.framework.CredentialIssuerBackend;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Default store-backed implementation of {@link CaService}.
 *
 * <p>
 * This service coordinates certification authority lifecycle operations against
 * the configured {@link PkiStore} and delegates format-specific certificate
 * issuance to the active {@link CredentialFramework}. The store acts as the
 * persistent source of truth for CA records and issued credentials, while this
 * class enforces the runtime orchestration rules required by the current PKI
 * implementation.
 * </p>
 *
 * <p>
 * Root CA creation is currently implemented directly in this class for the
 * internal X.509 runtime path. Intermediate CA certificate issuance is
 * delegated to the framework-provided issuer backend. Operations for CA
 * rollover and CA key rotation are intentionally exposed through the contract
 * but are not implemented in this runtime build.
 * </p>
 *
 * <h2>State and consistency</h2>
 * <ul>
 * <li>Each successful operation persists its resulting {@link CaRecord} and, if
 * applicable, the corresponding {@link Credential} into the configured
 * {@link PkiStore}.</li>
 * <li>CA lookup and listing operations read directly from the store and do not
 * maintain an internal cache.</li>
 * <li>This class is stateless apart from its immutable dependencies and runtime
 * configuration.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Private key material is never exported or retained by this service.</li>
 * <li>Cryptographic signing is delegated to {@link PkiSigningBus}, which allows
 * signing to be routed to an external signing workflow bound to a
 * {@link KeyRef}.</li>
 * <li>Log output is intentionally limited and must not contain secret material,
 * plaintext to-be-signed payloads, private keys, or other sensitive key
 * material.</li>
 * <li>The correctness of certificate format handling depends on the configured
 * {@link CredentialFramework} matching the requested format identifier.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances of this class are safe for concurrent use provided that the
 * injected collaborators, especially {@link PkiStore},
 * {@link CredentialFramework}, {@link PublicKeyInfoResolver}, and
 * {@link PkiSigningBus}, are themselves safe for the intended concurrency
 * model.
 * </p>
 */
// PMD cannot infer that retaining boundary causes would violate the redaction contract.
@SuppressWarnings({ "PMD.CouplingBetweenObjects", "PMD.CyclomaticComplexity",
        "PMD.ExcessiveParameterList", "PMD.PreserveStackTrace" })
public final class DefaultCaService implements CaService {

    private static final Logger LOG = Logger.getLogger(DefaultCaService.class.getName());
    private static final String CREATE_ROOT_REJECTED = "CREATE_ROOT_REJECTED";
    private static final String CREATE_INT_REJECTED = "CREATE_INTERMEDIATE_REJECTED";
    private static final String ISSUE_INT_REJECTED = "ISSUE_INTERMEDIATE_REJECTED";
    private static final String IMPORT_ROOT_REJECTED = "IMPORT_ROOT_REJECTED";
    private static final String BACKEND_CRED_MISMATCH = "BACKEND_CREDENTIAL_MISMATCH";
    private static final String ROOT_CREDENTIAL_INVALID = "ROOT_CREDENTIAL_INVALID";

    private final PkiStore store;
    private final CredentialFramework framework;
    private final CredentialIssuerBackend issuerBackend;
    private final CaProofGate proofGate;
    private final AuditSink auditSink;
    private final EffectiveCredentialStatusResolver statusResolver;
    private final ProfileService profileService;
    private final Clock clock;

    /**
     * Creates a CA service bound to a specific store, credential framework, and
     * signing runtime.
     *
     * <p>
     * The supplied collaborators define both the persistence boundary and the
     * cryptographic execution boundary of the service. In particular, certificate
     * signing is performed indirectly through the provided signing bus and never by
     * direct access to private key material.
     * </p>
     *
     * <p>
     * The {@code signatureAlgorithmId} is interpreted as a JCA signature algorithm
     * identifier and is used when this implementation performs direct X.509 root
     * certificate construction. The {@code signingTtl} defines the maximum time
     * window during which the service will wait for the delegated signing workflow
     * to complete.
     * </p>
     *
     * @param store                persistent PKI store used as the source of truth
     *                             for CA and credential records; must not be
     *                             {@code null}
     * @param framework            credential framework responsible for
     *                             format-specific issuance and validation paths;
     *                             must not be {@code null}
     * @param issuerBackend        privileged issuer implementation accepting only
     *                             proof-gated CA issuance inputs; must not be
     *                             {@code null}
     * @param publicKeyResolver    resolver used to obtain subject public key
     *                             material in SPKI DER form for key references;
     *                             must not be {@code null}
     * @param signingBus           signing orchestration component used to request
     *                             delegated signing operations; must not be
     *                             {@code null}
     * @param auditSink            required sink for safe CA proof rejection events;
     *                             must not be {@code null}
     * @param statusResolver       authoritative runtime credential-status resolver;
     *                             must not be {@code null}
     * @param signatureAlgorithmId non-blank JCA signature algorithm identifier used
     *                             for certificate signing requests initiated by
     *                             this service
     * @param signingTtl           positive maximum duration for delegated signing
     *                             completion
     * @throws NullPointerException     if any mandatory collaborator is
     *                                  {@code null}
     * @throws IllegalArgumentException if {@code signatureAlgorithmId} is
     *                                  {@code null}, blank, or if
     *                                  {@code signingTtl} is {@code null}, zero, or
     *                                  negative
     */
    public DefaultCaService(PkiStore store, CredentialFramework framework, CredentialIssuerBackend issuerBackend,
            PublicKeyInfoResolver publicKeyResolver, PkiSigningBus signingBus, AuditSink auditSink,
            EffectiveCredentialStatusResolver statusResolver, ProfileService profileService, Clock clock,
            String signatureAlgorithmId, Duration signingTtl) {

        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
        this.issuerBackend = Objects.requireNonNull(issuerBackend, "issuerBackend");
        Objects.requireNonNull(publicKeyResolver, "publicKeyResolver");
        Objects.requireNonNull(signingBus, "signingBus");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.statusResolver = Objects.requireNonNull(statusResolver, "statusResolver");
        this.profileService = Objects.requireNonNull(profileService, "profileService");
        this.clock = Objects.requireNonNull(clock, "clock");
        if (signatureAlgorithmId == null || signatureAlgorithmId.isBlank()) {
            throw new IllegalArgumentException("signatureAlgorithmId must not be null/blank");
        }
        if (signingTtl == null || signingTtl.isZero() || signingTtl.isNegative()) {
            throw new IllegalArgumentException("signingTtl must be positive");
        }
        this.proofGate = new CaProofGate(publicKeyResolver, signingBus, auditSink, signatureAlgorithmId, signingTtl);
    }

    /**
     * Creates and persists a new root CA together with its initial self-signed
     * credential.
     *
     * <p>
     * This implementation currently supports root creation only for the active
     * runtime format represented by the configured {@link CredentialFramework}. The
     * command is expected to reference an already available signing key through
     * {@link CaCreateCommand#keyRef()}; key generation is not performed here.
     * </p>
     *
     * <p>
     * The resulting root certificate is self-issued and self-signed. Its subject
     * and issuer distinguished names are identical and are derived from the
     * provided {@link SubjectRef}. The generated credential and CA identifier are
     * deterministically derived from the certificate content and the corresponding
     * public key material.
     * </p>
     *
     * @param command root CA creation command; must not be {@code null}
     * @return identifier of the persisted CA record
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the command does not contain a key reference,
     *                              if the requested format does not match the
     *                              configured runtime, if certificate construction
     *                              or signing fails, or if persistence cannot be
     *                              completed
     */
    @Override
    public PkiId createRoot(CaCreateCommand command) {
        Objects.requireNonNull(command, "command"); // NOPMD
        ActiveCertificateProfile activeProfile = profileService.requireActiveProfile(command.profileId());
        CaCertificateProfileValidator.requireProfileShape(activeProfile, CertificateProfileKind.ROOT_CA,
                command.formatId());
        Instant evaluationTime = clock.instant();
        if (command.keyRef().isEmpty()) {
            throw new PkiException("Root CA creation requires keyRef (key generation not wired)");
        }
        requireNoCaOverrides(command.attributes());
        if (!framework.formatId().equals(command.formatId())) {
            throw new PkiException("Unsupported formatId for this runtime");
        }
        KeyRef keyRef = command.keyRef().get();
        EncodedObject spki = proofGate.resolveManagedKey(keyRef, command.formatId(),
                CREATE_ROOT_REJECTED, Optional.empty());
        BigInteger serial = CertificateSerialAllocator.allocate();
        ValidatedCaCertificateRequest request = CaCertificateProfileValidator.validate(
                ValidatedCaCertificateRequest.Operation.CREATE_ROOT, activeProfile,
                CertificateProfileKind.ROOT_CA,
                command.formatId(), new PkiId("ca:pending-root"), new PkiId("ca:pending-root"),
                command.subjectRef(), spki, Optional.empty(), evaluationTime, Optional.empty(), serial);
        SubjectPublicKeyInfo rootPublicKeyInfo = proofGate.parseRootSpki(spki, command.formatId());
        CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(keyRef, command.formatId(),
                CREATE_ROOT_REJECTED, Optional.empty());
        requireSameManagedKey(spki, proof.exactPublicKey(), CREATE_ROOT_REJECTED,
                command.formatId(), Optional.empty());

        Validity validity = request.validity();
        X500Name dn = zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport.subject(request.subjectRdns());

        X509v3CertificateBuilder b = new X509v3CertificateBuilder(dn, serial, Date.from(validity.notBefore()),
                Date.from(validity.notAfter()), dn, rootPublicKeyInfo);
        try {
            b.addExtension(Extension.basicConstraints, request.policy().basicConstraintsCritical(),
                    new BasicConstraints(request.policy().pathLengthConstraint()));
            b.addExtension(Extension.keyUsage, request.policy().keyUsageCritical(),
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } catch (Exception ex) {
            throw new PkiException("Root extension construction failed: code=ROOT_EXTENSION_BUILD_FAILED");
        }

        ContentSigner signer = proofGate.signer(proof);
        X509CertificateHolder cert;
        try {
            cert = b.build(signer);
        } catch (RuntimeException ex) { // NOPMD
            throw proofGate.rejection(CREATE_ROOT_REJECTED, command.formatId(), Optional.empty(),
                    "ROOT_SIGNING_FAILED");
        }

        if (!proofGate.rootProofIsValid(cert, spki)) {
            throw proofGate.rejection(CREATE_ROOT_REJECTED, command.formatId(), Optional.empty(),
                    "ROOT_SELF_SIGNATURE_INVALID");
        }

        byte[] certDer;
        try {
            certDer = cert.getEncoded();
        } catch (Exception ex) {
            throw new PkiException("Root certificate encoding failed: code=ROOT_CERTIFICATE_ENCODE_FAILED");
        }

        PkiId credId = new PkiId("x509:" + sha256Hex(certDer));
        PkiId caId = new PkiId("ca:" + sha256Hex(certDer).substring(0, 16));

        PkiId publicKeyId = new PkiId("spki:" + sha256Hex(spki.bytes()));

        Credential credential = new Credential(credId, command.formatId(), new IssuerRef(caId), request.subjectRef(),
                validity, serial.toString(), publicKeyId, new CaProfileBinding(request.profileReference()),
                CredentialStatus.ISSUED, new EncodedObject(Encoding.DER, certDer),
                SimpleAttributeSet.builder().build());
        CredentialProfileBindings.requireCaBinding(credential.profileBinding(), request.profileReference());

        requireCaCertificateMatches(credential, credential, request, caId, CREATE_ROOT_REJECTED,
                BACKEND_CRED_MISMATCH);
        CaRecord ca = new CaRecord(caId, CaKind.ROOT, CaState.ACTIVE, keyRef, request.subjectRef(),
                List.of(credential));
        store.putCa(ca);
        store.putCredential(credential);
        return caId;
    }

    /**
     * Imports an existing root CA credential and persists the corresponding CA
     * record.
     *
     * <p>
     * This operation does not generate or modify the imported credential. Instead,
     * it validates the provided payload as an X.509 credential in DER encoding,
     * derives the PKI identifiers used by the runtime model, and stores both the
     * imported credential and the resulting root CA record.
     * </p>
     *
     * <p>
     * The imported certificate must be a self-issued, validly self-signed CA
     * certificate whose subject matches the command. The command's managed
     * {@link KeyRef} must also complete a signing challenge and resolve to the exact
     * certificate SPKI before either record is persisted.
     * </p>
     *
     * @param command root CA import command; must not be {@code null}
     * @return identifier of the persisted imported CA
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the requested format is unsupported, if the
     *                              payload is not DER encoded, if the X.509
     *                              structure is invalid, or if persistence fails
     */
    @Override
    public PkiId importRoot(CaImportCommand command) {
        Objects.requireNonNull(command, "command");
        ActiveCertificateProfile activeProfile = profileService.requireActiveProfile(command.profileId());
        CaCertificateProfileValidator.requireProfileShape(activeProfile, CertificateProfileKind.ROOT_CA,
                command.formatId());
        Instant evaluationTime = clock.instant();
        requireNoCaOverrides(command.attributes());
        if (!framework.formatId().equals(command.formatId())) {
            throw new PkiException("Unsupported formatId for this runtime");
        }
        if (command.existingCaCredential().encoding() != Encoding.DER) {
            throw new PkiException("Only DER import supported by this runtime");
        }

        byte[] certDer = command.existingCaCredential().bytes().clone();
        X509CertificateHolder holder;
        try {
            holder = new X509CertificateHolder(certDer);
        } catch (Exception ex) {
            throw new PkiException("Invalid X.509 credential: code=CREDENTIAL_INVALID");
        }

        Instant notBefore = holder.getNotBefore().toInstant();
        Instant notAfter = holder.getNotAfter().toInstant();
        Validity validity = new Validity(notBefore, notAfter);

        PkiId credId = new PkiId("x509:" + sha256Hex(certDer));
        PkiId caId = new PkiId("ca:" + sha256Hex(certDer).substring(0, 16));

        byte[] spkiDer;
        try {
            spkiDer = holder.getSubjectPublicKeyInfo().getEncoded();
        } catch (IOException ex) {
            throw new PkiException("Subject public key encoding failed: code=SPKI_ENCODE_FAILED");
        }

        PkiId publicKeyId = new PkiId("spki:" + sha256Hex(spkiDer));

        BigInteger serial = holder.getSerialNumber();
        EncodedObject spki = new EncodedObject(Encoding.DER, spkiDer);
        ValidatedCaCertificateRequest request = CaCertificateProfileValidator.validate(
                ValidatedCaCertificateRequest.Operation.IMPORT_ROOT, activeProfile,
                CertificateProfileKind.ROOT_CA,
                command.formatId(), caId, caId, command.subjectRef(), spki, Optional.of(validity),
                evaluationTime, Optional.empty(), serial);
        Credential credential = new Credential(credId, command.formatId(), new IssuerRef(caId), request.subjectRef(),
                validity, serial.toString(), publicKeyId, new CaProfileBinding(request.profileReference()),
                CredentialStatus.ISSUED,
                new EncodedObject(Encoding.DER, certDer), SimpleAttributeSet.builder().build());
        CredentialProfileBindings.requireCaBinding(credential.profileBinding(), request.profileReference());
        requireCaCertificateMatches(credential, credential, request, caId, IMPORT_ROOT_REJECTED,
                ROOT_CREDENTIAL_INVALID);
        requireValidImportedRoot(command, holder);
        store.putCredential(credential);
        CaRecord ca = new CaRecord(caId, CaKind.ROOT, CaState.ACTIVE, command.keyRef(), request.subjectRef(),
                List.of(credential));
        store.putCa(ca);
        return caId;
    }

    /**
     * Creates a new intermediate CA record and requests issuance of its initial CA
     * certificate.
     *
     * <p>
     * The subject CA record is created only after the corresponding intermediate
     * certificate has been issued successfully by the configured framework backend.
     * The issuer CA must already exist, must be in the {@link CaState#ACTIVE}
     * state, and must contain at least one CA credential usable as the issuing CA
     * identity.
     * </p>
     *
     * <p>
     * This method expects the subject signing key to be pre-provisioned and
     * referenced through {@link IntermediateCreateCommand#keyRef()}. No key
     * generation is performed by this service.
     * </p>
     *
     * <p>
     * Issuer credentials are evaluated against current revocation state and one
     * authoritative evaluation instant before managed-key proof or signing work.
     * Non-usable candidates are skipped; status-resolution failure aborts the
     * operation.
     * </p>
     *
     * @param command intermediate CA creation command; must not be {@code null}
     * @return identifier of the newly persisted intermediate CA
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if the subject key reference is missing, if the
     *                              issuer CA is unavailable or inactive, if the
     *                              issuer has no credentials, if certificate
     *                              issuance fails, or if persistence fails
     */
    @Override
    public PkiId createIntermediate(IntermediateCreateCommand command) {
        Objects.requireNonNull(command, "command");
        ActiveCertificateProfile activeProfile = profileService.requireActiveProfile(command.profileId());
        CaCertificateProfileValidator.requireProfileShape(activeProfile, CertificateProfileKind.INTERMEDIATE_CA,
                command.formatId());
        Instant evaluationTime = clock.instant();
        if (command.keyRef().isEmpty()) {
            throw new PkiException("Intermediate creation requires keyRef (key generation not wired)");
        }
        requireNoCaOverrides(command.attributes());

        CaRecord issuer = getCa(command.issuerCaId());
        ensureActive(issuer, "issuer");
        if (issuer.caCredentials().isEmpty()) {
            throw new PkiException("Issuer CA has no credentials");
        }
        if (!framework.formatId().equals(command.formatId())) {
            throw proofGate.rejection(CREATE_INT_REJECTED, command.formatId(), Optional.empty(),
                    "FORMAT_UNSUPPORTED");
        }
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCredential = CredentialSnapshots.copy(selectIssuerCredential(issuer, command.formatId(),
                CredentialUse.INTERMEDIATE_ISSUER, statusEvaluation));
        requireHistoricalCaProfile(issuerCredential,
                issuer.kind() == CaKind.ROOT ? CertificateProfileKind.ROOT_CA
                        : CertificateProfileKind.INTERMEDIATE_CA);

        List<zeroecho.pki.api.request.SubjectRdn> approvedSubject =
                CaCertificateProfileValidator.validateSubject(command.subjectRef(), activeProfile.definition());
        SubjectRef canonicalSubject = new SubjectRef(
                zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport.subject(approvedSubject).toString());
        PkiId caId = new PkiId("ca:" + sha256Hex((issuer.caId().value() + "\n" + canonicalSubject.value())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0, 16));

        EncodedObject subjectSpki = proofGate.resolveManagedKey(command.keyRef().get(),
                command.formatId(), CREATE_INT_REJECTED, Optional.of(caId));
        ValidatedCaCertificateRequest issue = CaCertificateProfileValidator.validateApprovedSubject(
                ValidatedCaCertificateRequest.Operation.CREATE_INTERMEDIATE, activeProfile,
                CertificateProfileKind.INTERMEDIATE_CA, command.formatId(), command.issuerCaId(), caId,
                approvedSubject, subjectSpki, Optional.empty(), evaluationTime,
                Optional.of(issuerCredential.validity().notAfter()), CertificateSerialAllocator.allocate());
        CaProofGate.ManagedKeyProof subjectProof = proofGate.proveManagedKey(command.keyRef().get(),
                command.formatId(), CREATE_INT_REJECTED, Optional.of(caId));
        requireSameManagedKey(subjectSpki, subjectProof.exactPublicKey(), CREATE_INT_REJECTED,
                command.formatId(), Optional.of(caId));
        requireIssuerKeyBinding(issuer, issuerCredential, command.formatId(), CREATE_INT_REJECTED,
                Optional.of(caId));

        Credential backendCredential;
        try {
            backendCredential = issuerBackend.issueIntermediateCertificate(issue, issuerCredential.encoded(),
                    issuer.issuerKeyRef());
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(CREATE_INT_REJECTED, command.formatId(), Optional.of(caId),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaBinding(backendCredential, issue.profileReference(), CREATE_INT_REJECTED,
                command.formatId(), Optional.of(caId));
        Credential cred;
        try {
            cred = CredentialSnapshots.copy(backendCredential);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(CREATE_INT_REJECTED, command.formatId(), Optional.of(caId),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaCertificateMatches(cred, issuerCredential, issue, caId, CREATE_INT_REJECTED,
                BACKEND_CRED_MISMATCH);
        store.putCredential(cred);

        CaRecord subject = new CaRecord(caId, CaKind.INTERMEDIATE, CaState.ACTIVE, command.keyRef().get(),
                issue.subjectRef(), List.of(cred));
        store.putCa(subject);
        return caId;
    }

    /**
     * Issues an additional intermediate CA certificate for an existing CA subject.
     *
     * <p>
     * Both the issuer and the subject CA must already exist and must be in the
     * {@link CaState#ACTIVE} state. The certificate issuance itself is delegated to
     * the active framework backend. On success, the newly issued credential is
     * stored and appended to the subject CA credential history.
     * </p>
     *
     * <p>
     * Issuer credentials are evaluated against current revocation state and one
     * authoritative evaluation instant before managed-key proof or signing work.
     * Non-usable candidates are skipped; status-resolution failure aborts the
     * operation.
     * </p>
     *
     * @param command intermediate certificate issuance command; must not be
     *                {@code null}
     * @return issued credential persisted for the subject CA
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         if either CA is missing or inactive, if issuance
     *                              fails, or if persistence fails
     */
    @Override
    public Credential issueIntermediateCertificate(IntermediateCertIssueCommand command) {
        Objects.requireNonNull(command, "command");
        ActiveCertificateProfile activeProfile = profileService.requireActiveProfile(command.profileId());
        CaCertificateProfileValidator.requireProfileShape(activeProfile, CertificateProfileKind.INTERMEDIATE_CA,
                command.formatId());
        Instant evaluationTime = clock.instant();
        requireNoCaOverrides(command.attributes());
        CaRecord issuer = getCa(command.issuerCaId());
        ensureActive(issuer, "issuer");
        CaRecord subject = getCa(command.subjectCaId());
        ensureActive(subject, "subject");
        if (subject.kind() != CaKind.INTERMEDIATE) {
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(),
                    Optional.of(subject.caId()), "CA_SUBJECT_KIND_INVALID");
        }
        if (!framework.formatId().equals(command.formatId())) {
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(),
                    Optional.of(subject.caId()),
                    "FORMAT_UNSUPPORTED");
        }
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCredential = CredentialSnapshots.copy(selectIssuerCredential(issuer, command.formatId(),
                CredentialUse.INTERMEDIATE_ISSUER, statusEvaluation));
        requireHistoricalCaProfile(issuerCredential,
                issuer.kind() == CaKind.ROOT ? CertificateProfileKind.ROOT_CA
                        : CertificateProfileKind.INTERMEDIATE_CA);

        List<zeroecho.pki.api.request.SubjectRdn> approvedSubject =
                CaCertificateProfileValidator.validateTrustedSubject(subject.subjectRef(),
                        activeProfile.definition());
        EncodedObject subjectSpki = proofGate.resolveManagedKey(subject.issuerKeyRef(),
                command.formatId(), ISSUE_INT_REJECTED, Optional.of(subject.caId()));
        ValidatedCaCertificateRequest gated = CaCertificateProfileValidator.validateApprovedSubject(
                ValidatedCaCertificateRequest.Operation.ISSUE_INTERMEDIATE, activeProfile,
                CertificateProfileKind.INTERMEDIATE_CA, command.formatId(), command.issuerCaId(),
                command.subjectCaId(), approvedSubject, subjectSpki, command.requestedValidity(),
                evaluationTime, Optional.of(issuerCredential.validity().notAfter()),
                CertificateSerialAllocator.allocate());
        CaProofGate.ManagedKeyProof subjectProof = proofGate.proveManagedKey(subject.issuerKeyRef(),
                command.formatId(), ISSUE_INT_REJECTED, Optional.of(subject.caId()));
        requireSameManagedKey(subjectSpki, subjectProof.exactPublicKey(), ISSUE_INT_REJECTED,
                command.formatId(), Optional.of(subject.caId()));
        requireIssuerKeyBinding(issuer, issuerCredential, command.formatId(), ISSUE_INT_REJECTED,
                Optional.of(subject.caId()));

        Credential backendCredential;
        try {
            backendCredential = issuerBackend.issueIntermediateCertificate(gated, issuerCredential.encoded(),
                    issuer.issuerKeyRef());
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(),
                    Optional.of(subject.caId()), BACKEND_CRED_MISMATCH);
        }
        requireCaBinding(backendCredential, gated.profileReference(), ISSUE_INT_REJECTED,
                command.formatId(), Optional.of(subject.caId()));
        Credential cred;
        try {
            cred = CredentialSnapshots.copy(backendCredential);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(),
                    Optional.of(subject.caId()), BACKEND_CRED_MISMATCH);
        }
        requireCaCertificateMatches(cred, issuerCredential, gated, subject.caId(), ISSUE_INT_REJECTED,
                BACKEND_CRED_MISMATCH);
        store.putCredential(cred);

        List<Credential> updated = new ArrayList<>(subject.caCredentials());
        updated.add(cred);
        CaRecord updatedCa = new CaRecord(subject.caId(), subject.kind(), subject.state(), subject.issuerKeyRef(),
                subject.subjectRef(), List.copyOf(updated));
        store.putCa(updatedCa);
        return cred;
    }

    /**
     * Requests CA certificate rollover.
     *
     * <p>
     * The {@link CaService} contract exposes this capability, but the current
     * runtime build does not implement it.
     * </p>
     *
     * @param command rollover request; must not be {@code null}
     * @return never returns normally
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         always, because CA rollover is not implemented
     *                              in this runtime build
     */
    @Override
    public PkiId rolloverCaCertificate(CaRolloverCommand command) {
        Objects.requireNonNull(command, "command");
        throw new PkiException("CA rollover is not implemented in this runtime build");
    }

    /**
     * Requests CA key rotation.
     *
     * <p>
     * The {@link CaService} contract exposes this capability, but the current
     * runtime build does not implement it.
     * </p>
     *
     * @param command key rotation request; must not be {@code null}
     * @return never returns normally
     * @throws NullPointerException if {@code command} is {@code null}
     * @throws PkiException         always, because CA key rotation is not
     *                              implemented in this runtime build
     */
    @Override
    public PkiId rotateCaKey(CaKeyRotationCommand command) {
        Objects.requireNonNull(command, "command");
        throw new PkiException("CA key rotation is not implemented in this runtime build");
    }

    /**
     * Updates the lifecycle state of an existing CA record.
     *
     * <p>
     * When the requested state equals the currently persisted state, this method is
     * a no-op. Otherwise, the CA record is rewritten with the new state while
     * preserving all other persisted fields.
     * </p>
     *
     * <p>
     * The supplied {@code reason} is validated as mandatory caller intent even
     * though the current implementation only logs the state change and does not
     * persist the reason itself.
     * </p>
     *
     * @param caId   identifier of the CA to update; must not be {@code null}
     * @param state  target CA state; must not be {@code null}
     * @param reason non-blank caller-supplied reason for the state transition
     * @throws NullPointerException     if {@code caId} or {@code state} is
     *                                  {@code null}
     * @throws IllegalArgumentException if {@code reason} is {@code null} or blank
     * @throws PkiException             if the CA does not exist or the updated
     *                                  record cannot be persisted
     */
    @Override
    public void setCaState(PkiId caId, CaState state, String reason) {
        Objects.requireNonNull(caId, "caId");
        Objects.requireNonNull(state, "state");
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be null/blank");
        }

        CaRecord existing = getCa(caId);
        if (existing.state() == state) {
            return;
        }

        CaRecord updated = new CaRecord(existing.caId(), existing.kind(), state, existing.issuerKeyRef(),
                existing.subjectRef(), existing.caCredentials());
        store.putCa(updated);

        if (LOG.isLoggable(Level.INFO)) {
            LOG.log(Level.INFO, "CA state updated for caId={0}", caId.value());
        }
    }

    /**
     * Resolves a CA record by its identifier.
     *
     * @param caId identifier of the CA to resolve; must not be {@code null}
     * @return persisted CA record
     * @throws NullPointerException if {@code caId} is {@code null}
     * @throws PkiException         if no CA with the supplied identifier exists
     */
    @Override
    public CaRecord getCa(PkiId caId) {
        Objects.requireNonNull(caId, "caId");
        return store.getCa(caId).orElseThrow(() -> new PkiException("CA not found"));
    }

    /**
     * Lists CA records matching the supplied query constraints.
     *
     * <p>
     * Filtering is performed in-memory over the current store contents. Only the
     * constraints present in the {@link CaQuery} are applied. When a format
     * identifier filter is present, the last credential associated with each CA is
     * used as the effective credential format representative.
     * </p>
     *
     * @param query CA selection criteria; must not be {@code null}
     * @return immutable list of CA records matching the requested criteria; never
     *         {@code null}
     * @throws NullPointerException if {@code query} is {@code null}
     */
    @Override
    public List<CaRecord> listCas(CaQuery query) {
        Objects.requireNonNull(query, "query");
        List<CaRecord> all = store.listCas();
        return all.stream().filter(r -> {
            if (query.kind().isPresent() && query.kind().get() != r.kind()) {
                return false;
            }
            if (query.state().isPresent() && query.state().get() != r.state()) {
                return false;
            }
            if (query.subjectRef().isPresent() && !query.subjectRef().get().equals(r.subjectRef())) {
                return false;
            }
            if (query.formatId().isPresent()) {
                if (r.caCredentials().isEmpty()) {
                    return false;
                }
                Credential last = r.caCredentials().get(r.caCredentials().size() - 1);
                return query.formatId().get().equals(last.formatId());
            }
            return true;
        }).toList();
    }

    private static void ensureActive(CaRecord ca, String role) {
        if (ca.state() != CaState.ACTIVE) {
            throw new PkiException("CA not ACTIVE: " + role);
        }
    }

    private Credential selectIssuerCredential(CaRecord issuer, FormatId formatId, CredentialUse use,
            EffectiveCredentialStatusResolver.Evaluation evaluation) {
        Credential lastRejected = null;
        EffectiveCredentialStatus lastStatus = null;
        for (Credential credential : issuer.caCredentials()) {
            if (credential == null || !formatId.equals(credential.formatId())) {
                continue;
            }
            EffectiveCredentialStatus status;
            try {
                status = evaluation.resolve(credential);
            } catch (PkiException exception) {
                CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), credential, use,
                        StoreBackedEffectiveCredentialStatusResolver.RESOLUTION_FAILED_CODE, null);
                throw exception;
            }
            if (status == EffectiveCredentialStatus.USABLE) {
                return credential;
            }
            lastRejected = credential;
            lastStatus = status;
        }
        if (lastRejected != null) {
            CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), lastRejected, use,
                    "ISSUER_CREDENTIAL_UNAVAILABLE", lastStatus);
        }
        throw new PkiException("Issuer credential unavailable: code=ISSUER_CREDENTIAL_UNAVAILABLE");
    }

    private void requireValidImportedRoot(CaImportCommand command, X509CertificateHolder holder) {
        try {
            CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(command.keyRef(), command.formatId(),
                    IMPORT_ROOT_REJECTED, Optional.empty());
            if (!MessageDigest.isEqual(proof.exactPublicKey().bytes(), holder.getSubjectPublicKeyInfo().getEncoded())) {
                throw proofGate.rejection(IMPORT_ROOT_REJECTED, command.formatId(), Optional.empty(),
                        "ROOT_MANAGED_KEY_MISMATCH");
            }
        } catch (PkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw proofGate.rejection(IMPORT_ROOT_REJECTED, command.formatId(), Optional.empty(),
                    ROOT_CREDENTIAL_INVALID);
        }
    }

    private void requireIssuerKeyBinding(CaRecord issuer, Credential credential, FormatId formatId, String action,
            Optional<PkiId> objectId) {
        try {
            if (credential.encoded().encoding() != Encoding.DER) {
                throw proofGate.rejection(action, formatId, objectId, "ISSUER_CREDENTIAL_INVALID");
            }
            X509CertificateHolder holder = new X509CertificateHolder(credential.encoded().bytes());
            CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(issuer.issuerKeyRef(), formatId, action,
                    objectId);
            if (!MessageDigest.isEqual(proof.exactPublicKey().bytes(),
                    holder.getSubjectPublicKeyInfo().getEncoded())) {
                throw proofGate.rejection(action, formatId, objectId, "ISSUER_MANAGED_KEY_MISMATCH");
            }
        } catch (PkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw proofGate.rejection(action, formatId, objectId, "ISSUER_CREDENTIAL_INVALID");
        }
    }

    private void requireCaCertificateMatches(Credential credential, Credential issuerCredential,
            ValidatedCaCertificateRequest request, PkiId subjectCaId, String action, String mismatchCode) {
        try {
            if (!matchesCaCredentialEnvelope(credential, request, subjectCaId)) {
                throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId),
                        mismatchCode);
            }
            X509CertificateHolder holder = new X509CertificateHolder(credential.encoded().bytes());
            X509CertificateHolder issuerHolder = new X509CertificateHolder(issuerCredential.encoded().bytes());
            byte[] actualSpki = holder.getSubjectPublicKeyInfo().getEncoded();
            Extension constraintsExtension = holder.getExtension(Extension.basicConstraints);
            BasicConstraints constraints = constraintsExtension == null ? null
                    : BasicConstraints.getInstance(constraintsExtension.getParsedValue());
            Extension keyUsageExtension = holder.getExtension(Extension.keyUsage);
            KeyUsage keyUsage = keyUsageExtension == null ? null
                    : KeyUsage.getInstance(keyUsageExtension.getParsedValue());
            X500Name expectedSubject =
                    zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport.subject(request.subjectRdns());
            X500Name expectedIssuer = request.certificateType() == CertificateProfileKind.ROOT_CA
                    ? expectedSubject : issuerHolder.getSubject();
            if (!matchesCaCertificateIdentity(holder, issuerHolder, request, expectedSubject, expectedIssuer,
                    actualSpki)
                    || !matchesCaCertificatePolicy(holder, request, constraintsExtension, constraints,
                            keyUsageExtension, keyUsage)
                    || !matchesCaCredentialMetadata(credential, holder, request, actualSpki)) {
                throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId),
                        mismatchCode);
            }
            CredentialProfileBindings.requireCaBinding(credential.profileBinding(), request.profileReference());
        } catch (PkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId),
                    mismatchCode);
        }
    }

    private boolean matchesCaCredentialEnvelope(Credential credential, ValidatedCaCertificateRequest request,
            PkiId subjectCaId) {
        return framework.formatId().equals(credential.formatId())
                && credential.encoded().encoding() == Encoding.DER
                && credential.status() == CredentialStatus.ISSUED
                && credential.subjectRef().equals(request.subjectRef())
                && credential.issuerRef().equals(new IssuerRef(
                        request.certificateType() == CertificateProfileKind.ROOT_CA
                                ? subjectCaId : request.issuerCaId()));
    }

    private static boolean matchesCaCertificateIdentity(X509CertificateHolder holder,
            X509CertificateHolder issuerHolder, ValidatedCaCertificateRequest request, X500Name expectedSubject,
            X500Name expectedIssuer, byte[] actualSpki)
            throws IOException, OperatorCreationException, CertException {
        return MessageDigest.isEqual(request.exactPublicKey().bytes(), actualSpki)
                && MessageDigest.isEqual(holder.getSubject().getEncoded(), expectedSubject.getEncoded())
                && MessageDigest.isEqual(holder.getIssuer().getEncoded(), expectedIssuer.getEncoded())
                && holder.isSignatureValid(
                        new JcaContentVerifierProviderBuilder().build(issuerHolder.getSubjectPublicKeyInfo()));
    }

    private static boolean matchesCaCertificatePolicy(X509CertificateHolder holder,
            ValidatedCaCertificateRequest request, Extension constraintsExtension, BasicConstraints constraints,
            Extension keyUsageExtension, KeyUsage keyUsage) {
        return constraintsExtension != null && constraintsExtension.isCritical()
                && constraints != null && constraints.isCA()
                && BigInteger.valueOf(request.policy().pathLengthConstraint())
                        .equals(constraints.getPathLenConstraint())
                && keyUsageExtension != null && keyUsageExtension.isCritical()
                && hasIntermediateKeyUsage(keyUsage)
                && holder.getExtensions().getExtensionOIDs().length == 2;
    }

    private static boolean matchesCaCredentialMetadata(Credential credential, X509CertificateHolder holder,
            ValidatedCaCertificateRequest request, byte[] actualSpki) {
        return credential.publicKeyId().equals(new PkiId("spki:" + sha256Hex(actualSpki)))
                && credential.credentialId()
                        .equals(new PkiId("x509:" + sha256Hex(credential.encoded().bytes())))
                && credential.serialOrUniqueId().equals(holder.getSerialNumber().toString())
                && credential.validity().notBefore().getEpochSecond() == holder.getNotBefore().toInstant()
                        .getEpochSecond()
                && credential.validity().notAfter().getEpochSecond() == holder.getNotAfter().toInstant()
                        .getEpochSecond()
                && credential.validity().equals(request.validity())
                && credential.serialOrUniqueId().equals(request.serial().toString())
                && credential.attributes().ids().isEmpty();
    }

    private void requireCaBinding(Credential credential,
            zeroecho.pki.api.profile.CertificateProfileRef expectedCaProfile, String action,
            FormatId formatId, Optional<PkiId> objectId) {
        try {
            CredentialProfileBindings.requireCaBinding(
                    credential == null ? null : credential.profileBinding(), expectedCaProfile);
        } catch (PkiException mismatch) {
            throw proofGate.rejection(action, formatId, objectId, CredentialProfileBindings.MISMATCH_CODE);
        }
    }

    private static boolean hasIntermediateKeyUsage(KeyUsage keyUsage) {
        if (keyUsage == null || !keyUsage.hasUsages(KeyUsage.keyCertSign | KeyUsage.cRLSign)) {
            return false;
        }
        return !keyUsage.hasUsages(KeyUsage.digitalSignature)
                && !keyUsage.hasUsages(KeyUsage.nonRepudiation)
                && !keyUsage.hasUsages(KeyUsage.keyEncipherment)
                && !keyUsage.hasUsages(KeyUsage.dataEncipherment)
                && !keyUsage.hasUsages(KeyUsage.keyAgreement)
                && !keyUsage.hasUsages(KeyUsage.encipherOnly)
                && !keyUsage.hasUsages(KeyUsage.decipherOnly);
    }

    private static void requireNoCaOverrides(AttributeSet attributes) {
        if (!attributes.ids().isEmpty()) {
            throw new PkiException("CA certificate profile rejected: code=CA_REQUEST_ATTRIBUTE_UNSUPPORTED");
        }
    }

    private void requireHistoricalCaProfile(Credential credential, CertificateProfileKind expectedKind) {
        if (!(credential.profileBinding() instanceof CaProfileBinding binding)) {
            throw new PkiException("CA issuer profile rejected: code=CREDENTIAL_PROFILE_BINDING_MISMATCH");
        }
        zeroecho.pki.api.profile.CertificateProfileRef reference = binding.reference();
        zeroecho.pki.api.profile.ImportedCertificateProfileVersion version = profileService
                .getImportedVersion(reference.profileId(), reference.profileVersion())
                .orElseThrow(() -> new PkiException("CA issuer profile rejected: code=CA_PROFILE_VERSION_MISSING"));
        if (!version.reference().equals(reference) || version.definition().certificateType() != expectedKind
                || !version.definition().formatId().equals(credential.formatId())
                || !credential.formatId().equals(framework.formatId())) {
            throw new PkiException("CA issuer profile rejected: code=CA_PROFILE_REFERENCE_MISMATCH");
        }
    }

    private void requireSameManagedKey(EncodedObject expected, EncodedObject actual, String action,
            FormatId formatId, Optional<PkiId> objectId) {
        if (expected.encoding() != actual.encoding()
                || !MessageDigest.isEqual(expected.bytes(), actual.bytes())) {
            throw proofGate.rejection(action, formatId, objectId, "MANAGED_KEY_CHANGED");
        }
    }

    private static String sha256Hex(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(in));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }

}
