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
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import zeroecho.pkix.BasicConstraints;
import zeroecho.pkix.KeyUsage;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cert.CertificateBuilder;

import zeroecho.core.io.CancellationSignal;

import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.core.spi.AlgorithmExecutionCapability;
import zeroecho.pki.api.CaService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SigningExecutionException;
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
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.profile.CertificateProfileRef;
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
import zeroecho.pki.impl.core.async.DomainCommandEncoding;
import zeroecho.pki.impl.core.async.DomainContinuationTemplate;
import zeroecho.pki.impl.core.async.PendingSigningOperation;
import zeroecho.pki.spi.store.DomainContinuationStore;
import zeroecho.pki.impl.framework.x509.X509ExecutionPlan;
import zeroecho.pki.impl.framework.x509.bc.PkiBusContentSigner;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
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
// The service keeps CA lifecycle, credential, policy, audit, and signing collaborators together so
// state transitions remain one boundary; retaining boundary causes would also violate redaction.
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.ExcessiveParameterList",
        "PMD.PreserveStackTrace", "PMD.CouplingBetweenObjects" })
public final class DefaultCaService implements CaService {

    private static final Logger LOG = Logger.getLogger(DefaultCaService.class.getName());
    private static final String CANCELLATION_PARAMETER = "cancellation";
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
    private final zeroecho.pki.impl.framework.x509.X509AuthoritySnapshot authority;
    private final AuditSink auditSink;
    private final EffectiveCredentialStatusResolver statusResolver;
    private final ProfileService profileService;
    private final Clock clock;
    private final AlgorithmIdentity signatureIdentity;

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
     * @param profileService authoritative certificate-profile service
     * @param clock authoritative service clock
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
        this(store, framework, issuerBackend, publicKeyResolver, signingBus, auditSink, statusResolver, profileService,
                clock, signatureAlgorithmId, Optional.empty(), signingTtl);
    }

    /**
     * Creates a CA service with an optional explicit X.509 signature binding.
     *
     * @param store persistent PKI store
     * @param framework credential framework
     * @param issuerBackend issuer backend
     * @param publicKeyResolver managed public-key resolver
     * @param signingBus signing bus
     * @param auditSink audit sink
     * @param statusResolver effective status resolver
     * @param profileService profile service
     * @param clock injected clock
     * @param signatureAlgorithmId cryptographic signature identity
     * @param signatureBindingId explicit binding identity, when private mode is selected
     * @param signingTtl signing operation time-to-live
     */
    public DefaultCaService(PkiStore store, CredentialFramework framework, CredentialIssuerBackend issuerBackend,
            PublicKeyInfoResolver publicKeyResolver, PkiSigningBus signingBus, AuditSink auditSink,
            EffectiveCredentialStatusResolver statusResolver, ProfileService profileService, Clock clock,
            String signatureAlgorithmId, Optional<String> signatureBindingId, Duration signingTtl) {

        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
        this.issuerBackend = Objects.requireNonNull(issuerBackend, "issuerBackend");
        Objects.requireNonNull(publicKeyResolver, "publicKeyResolver");
        Objects.requireNonNull(signingBus, "signingBus");
        this.authority = signingBus.authority();
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
        AlgorithmIdentity signatureIdentity = signingBus.authority().resolveIdentity(signatureAlgorithmId);
        String implementation = signingBus.defaultSigningImplementationId();
        X509ExecutionPlan<SignatureWorkflow> plan = signatureBindingId.isPresent()
                ? signingBus.authority().planSigningWithBinding(signatureIdentity.canonicalForm(),
                        signatureBindingId.orElseThrow(), implementation, SignatureWorkflow.class)
                : signingBus.authority().planSigning(signatureIdentity.canonicalForm(), implementation,
                        SignatureWorkflow.class);
        signingBus.authority().authorize(plan, plan.executor(), AlgorithmExecutionCapability.Direction.SIGN);
        this.signatureIdentity = signatureIdentity;
        this.proofGate = new CaProofGate(publicKeyResolver, signingBus, auditSink, signatureIdentity,
                signatureBindingId, signingTtl);
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
        return createRoot(command, CancellationSignal.NONE);
    }

    @Override
    public PkiId createRoot(CaCreateCommand command, CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
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
        EncodedObject spki = proofGate.resolveManagedKey(keyRef, command.formatId(), CREATE_ROOT_REJECTED,
                Optional.empty());
        BigInteger serial = CertificateSerialAllocator.allocate();
        ValidatedCaCertificateRequest request = CaCertificateProfileValidator.validate(
                ValidatedCaCertificateRequest.Operation.CREATE_ROOT, activeProfile, CertificateProfileKind.ROOT_CA,
                command.formatId(), new PkiId("ca:pending-root"), new PkiId("ca:pending-root"), command.subjectRef(),
                spki, Optional.empty(), evaluationTime, Optional.empty(), serial, authority);
        byte[] rootPublicKeyInfo = proofGate.parseRootSpki(spki, command.formatId());
        CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(keyRef, command.formatId(), CREATE_ROOT_REJECTED,
                Optional.empty(), cancellation);
        requireSameManagedKey(spki, proof.exactPublicKey(), CREATE_ROOT_REJECTED, command.formatId(), Optional.empty());

        Validity validity = request.validity();
        X500Principal dn = zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport.subject(request.subjectRdns());

        CertificateBuilder b = Pkix.certificateBuilder().issuer(dn).serialNumber(serial)
                .validity(validity.notBefore(), validity.notAfter()).subject(dn).publicKeyInfo(rootPublicKeyInfo);
        try {
            b.basicConstraints(BasicConstraints.ca(request.policy().pathLengthConstraint()),
                    request.policy().basicConstraintsCritical());
            b.keyUsage(java.util.EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                    request.policy().keyUsageCritical());
        } catch (Exception ex) {
            throw new PkiException("Root extension construction failed: code=ROOT_EXTENSION_BUILD_FAILED");
        }

        X509Certificate cert;
        DomainContinuationTemplate domain = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                "CREATE_ROOT", command.formatId().value(), command.subjectRef().value(), command.profileId(),
                keyRef.value(), request.profileReference().profileId(),
                Long.toString(request.profileReference().profileVersion()),
                HexFormat.of().formatHex(request.profileReference().canonicalSha256()),
                request.validity().notBefore().toString(), request.validity().notAfter().toString(),
                request.serial().toString(), request.subjectRdns().toString(), request.policy().toString(),
                request.algorithmBindingPolicy().toString());
        try (PkiBusContentSigner signer = proofGate.signer(proof, request.algorithmBindingPolicy(), cancellation,
                domain)) {
            cert = b.build(signer);
        } catch (PendingSigningOperation | SigningExecutionException signingFailure) {
            throw signingFailure;
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
        PkiId issuerId = IssuerGeneration.idFor(caId, credId);
        IssuerChainPath rootPath = IssuerAuthorities.rootPath(caId, issuerId, credId);

        PkiId publicKeyId = new PkiId("spki:" + sha256Hex(spki.bytes()));

        Credential credential = new Credential(credId, command.formatId(),
                new IssuerRef(caId, issuerId, rootPath.pathId()), request.subjectRef(),
                validity, serial.toString(), publicKeyId, new CaProfileBinding(request.profileReference()),
                CredentialStatus.ISSUED, CredentialContent.stage(store, certDer),
                SimpleAttributeSet.builder().build());
        CredentialProfileBindings.requireCaBinding(credential.profileBinding(), request.profileReference());

        requireCaCertificateMatches(credential, credential, request, caId, CREATE_ROOT_REJECTED, BACKEND_CRED_MISMATCH);
        store.putCredential(credential);
        store.putIssuerGeneration(IssuerAuthorities.generation(caId, keyRef, credential));
        store.putIssuerChainPath(rootPath);
        CaRecord ca = new CaRecord(caId, CaKind.ROOT, CaState.ACTIVE, keyRef, request.subjectRef(),
                List.of(issuerId), issuerId, rootPath.pathId());
        store.putCa(ca);
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
     * {@link KeyRef} must also complete a signing challenge and resolve to the
     * exact certificate SPKI before either record is persisted.
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
        return importRoot(command, CancellationSignal.NONE);
    }

    // X.509 providers expose parse and accessor failures through provider-specific exception subtypes.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    @Override
    public PkiId importRoot(CaImportCommand command, CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
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

        CredentialContent.validateCertificate(store, command.existingCaCredential(), authority, Optional.empty());
        byte[] certDer = CredentialContent.materializeForBc(store, command.existingCaCredential());
        X509Certificate holder;
        try {
            holder = Pkix.parseCertificate(certDer);
        } catch (Exception ex) {
            throw new PkiException("Invalid X.509 credential: code=CREDENTIAL_INVALID", ex);
        }

        Instant notBefore = holder.getNotBefore().toInstant();
        Instant notAfter = holder.getNotAfter().toInstant();
        Validity validity = new Validity(notBefore, notAfter);

        PkiId credId = new PkiId("x509:" + sha256Hex(certDer));
        PkiId caId = new PkiId("ca:" + sha256Hex(certDer).substring(0, 16));
        PkiId issuerId = IssuerGeneration.idFor(caId, credId);
        IssuerChainPath rootPath = IssuerAuthorities.rootPath(caId, issuerId, credId);

        byte[] spkiDer;
        try {
            spkiDer = Pkix.subjectPublicKeyInfo(holder);
        } catch (RuntimeException ex) {
            throw new PkiException("Subject public key encoding failed: code=SPKI_ENCODE_FAILED", ex);
        }

        PkiId publicKeyId = new PkiId("spki:" + sha256Hex(spkiDer));

        BigInteger serial = holder.getSerialNumber();
        EncodedObject spki = new EncodedObject(Encoding.DER, spkiDer);
        ValidatedCaCertificateRequest request = CaCertificateProfileValidator.validate(
                ValidatedCaCertificateRequest.Operation.IMPORT_ROOT, activeProfile, CertificateProfileKind.ROOT_CA,
                command.formatId(), caId, caId, command.subjectRef(), spki, Optional.of(validity), evaluationTime,
                Optional.empty(), serial, authority);
        Credential credential = new Credential(credId, command.formatId(),
                new IssuerRef(caId, issuerId, rootPath.pathId()), request.subjectRef(),
                validity, serial.toString(), publicKeyId, new CaProfileBinding(request.profileReference()),
                CredentialStatus.ISSUED, command.existingCaCredential(),
                SimpleAttributeSet.builder().build());
        CredentialProfileBindings.requireCaBinding(credential.profileBinding(), request.profileReference());
        requireCaCertificateMatches(credential, credential, request, caId, IMPORT_ROOT_REJECTED,
                ROOT_CREDENTIAL_INVALID);
        requireValidImportedRoot(command, holder, cancellation);
        store.putCredential(credential);
        store.putIssuerGeneration(IssuerAuthorities.generation(caId, command.keyRef(), credential));
        store.putIssuerChainPath(rootPath);
        CaRecord ca = new CaRecord(caId, CaKind.ROOT, CaState.ACTIVE, command.keyRef(), request.subjectRef(),
                List.of(issuerId), issuerId, rootPath.pathId());
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
        return createIntermediate(command, CancellationSignal.NONE);
    }

    @Override
    public PkiId createIntermediate(IntermediateCreateCommand command, CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
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
        if (!framework.formatId().equals(command.formatId())) {
            throw proofGate.rejection(CREATE_INT_REJECTED, command.formatId(), Optional.empty(), "FORMAT_UNSUPPORTED");
        }
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCredential = CredentialSnapshots.copy(selectIssuerCredential(issuer, command.formatId(),
                CredentialUse.INTERMEDIATE_ISSUER, statusEvaluation));
        IssuerGeneration parentGeneration = IssuerAuthorities.current(store, issuer);
        IssuerChainPath parentPath = IssuerAuthorities.issuancePath(store, issuer);
        requireHistoricalCaProfile(issuerCredential,
                issuer.kind() == CaKind.ROOT ? CertificateProfileKind.ROOT_CA : CertificateProfileKind.INTERMEDIATE_CA);

        List<zeroecho.pki.api.request.SubjectRdn> approvedSubject = CaCertificateProfileValidator
                .validateSubject(command.subjectRef(), activeProfile.definition());
        SubjectRef canonicalSubject = new SubjectRef(
                zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport.subjectRefString(approvedSubject));
        PkiId caId = new PkiId("ca:" + sha256Hex((issuer.caId().value() + "\n" + canonicalSubject.value())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0, 16));

        EncodedObject subjectSpki = proofGate.resolveManagedKey(command.keyRef().get(), command.formatId(),
                CREATE_INT_REJECTED, Optional.of(caId));
        ValidatedCaCertificateRequest issue = CaCertificateProfileValidator.validateApprovedSubject(
                ValidatedCaCertificateRequest.Operation.CREATE_INTERMEDIATE, activeProfile,
                CertificateProfileKind.INTERMEDIATE_CA, command.formatId(), command.issuerCaId(), caId, approvedSubject,
                subjectSpki, Optional.empty(), evaluationTime, Optional.of(issuerCredential.validity().notAfter()),
                CertificateSerialAllocator.allocate(), authority);
        issue = issue.withFrozenPublication(parentGeneration.issuerId(), parentPath.pathId(),
                parentPath.pathCommitment(), command.keyRef().orElseThrow());
        CaProofGate.ManagedKeyProof subjectProof = proofGate.proveManagedKey(command.keyRef().get(), command.formatId(),
                CREATE_INT_REJECTED, Optional.of(caId), cancellation);
        requireSameManagedKey(subjectSpki, subjectProof.exactPublicKey(), CREATE_INT_REJECTED, command.formatId(),
                Optional.of(caId));
        requireIssuerKeyBinding(issuer, issuerCredential, command.formatId(), CREATE_INT_REJECTED,
                Optional.of(caId), cancellation);

        Credential backendCredential;
        try {
            backendCredential = issuerBackend.issueIntermediateCertificate(issue, issuerCredential.content(),
                    issuer.issuerKeyRef(), cancellation);
        } catch (PendingSigningOperation | SigningExecutionException signingFailure) {
            throw signingFailure;
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(CREATE_INT_REJECTED, command.formatId(), Optional.of(caId),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaBinding(backendCredential, issue.profileReference(), CREATE_INT_REJECTED, command.formatId(),
                Optional.of(caId));
        Credential rawCredential;
        try {
            rawCredential = CredentialSnapshots.copy(backendCredential);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(CREATE_INT_REJECTED, command.formatId(), Optional.of(caId),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaCertificateMatches(rawCredential, issuerCredential, issue, caId, CREATE_INT_REJECTED,
                BACKEND_CRED_MISMATCH);
        Credential cred = IssuerAuthorities.withIssuer(rawCredential,
                new IssuerRef(issuer.caId(), parentGeneration.issuerId(), parentPath.pathId()));
        store.putCredential(cred);
        IssuerGeneration subjectGeneration = IssuerAuthorities.generation(caId,
                command.keyRef().orElseThrow(), cred);
        IssuerChainPath subjectPath = IssuerAuthorities.childPath(caId,
                subjectGeneration.issuerId(), cred.credentialId(), parentPath);
        store.putIssuerGeneration(subjectGeneration);
        store.putIssuerChainPath(subjectPath);

        CaRecord subject = new CaRecord(caId, CaKind.INTERMEDIATE, CaState.ACTIVE, command.keyRef().get(),
                issue.subjectRef(), List.of(subjectGeneration.issuerId()), subjectGeneration.issuerId(),
                subjectPath.pathId());
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
        return issueIntermediateCertificate(command, CancellationSignal.NONE);
    }

    @Override
    public Credential issueIntermediateCertificate(IntermediateCertIssueCommand command,
            CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
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
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(), Optional.of(subject.caId()),
                    "CA_SUBJECT_KIND_INVALID");
        }
        if (!framework.formatId().equals(command.formatId())) {
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(), Optional.of(subject.caId()),
                    "FORMAT_UNSUPPORTED");
        }
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCredential = CredentialSnapshots.copy(selectIssuerCredential(issuer, command.formatId(),
                CredentialUse.INTERMEDIATE_ISSUER, statusEvaluation));
        IssuerGeneration parentGeneration = IssuerAuthorities.current(store, issuer);
        IssuerChainPath parentPath = IssuerAuthorities.issuancePath(store, issuer);
        requireHistoricalCaProfile(issuerCredential,
                issuer.kind() == CaKind.ROOT ? CertificateProfileKind.ROOT_CA : CertificateProfileKind.INTERMEDIATE_CA);

        List<zeroecho.pki.api.request.SubjectRdn> approvedSubject = CaCertificateProfileValidator
                .validateTrustedSubject(subject.subjectRef(), activeProfile.definition());
        EncodedObject subjectSpki = proofGate.resolveManagedKey(subject.issuerKeyRef(), command.formatId(),
                ISSUE_INT_REJECTED, Optional.of(subject.caId()));
        ValidatedCaCertificateRequest gated = CaCertificateProfileValidator.validateApprovedSubject(
                ValidatedCaCertificateRequest.Operation.ISSUE_INTERMEDIATE, activeProfile,
                CertificateProfileKind.INTERMEDIATE_CA, command.formatId(), command.issuerCaId(), command.subjectCaId(),
                approvedSubject, subjectSpki, command.requestedValidity(), evaluationTime,
                Optional.of(issuerCredential.validity().notAfter()), CertificateSerialAllocator.allocate(),
                authority);
        gated = gated.withFrozenPublication(parentGeneration.issuerId(), parentPath.pathId(),
                parentPath.pathCommitment(), subject.issuerKeyRef());
        CaProofGate.ManagedKeyProof subjectProof = proofGate.proveManagedKey(subject.issuerKeyRef(), command.formatId(),
                ISSUE_INT_REJECTED, Optional.of(subject.caId()), cancellation);
        requireSameManagedKey(subjectSpki, subjectProof.exactPublicKey(), ISSUE_INT_REJECTED, command.formatId(),
                Optional.of(subject.caId()));
        requireIssuerKeyBinding(issuer, issuerCredential, command.formatId(), ISSUE_INT_REJECTED,
                Optional.of(subject.caId()), cancellation);

        Credential backendCredential;
        try {
            backendCredential = issuerBackend.issueIntermediateCertificate(gated, issuerCredential.content(),
                    issuer.issuerKeyRef(), cancellation);
        } catch (PendingSigningOperation | SigningExecutionException signingFailure) {
            throw signingFailure;
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(), Optional.of(subject.caId()),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaBinding(backendCredential, gated.profileReference(), ISSUE_INT_REJECTED, command.formatId(),
                Optional.of(subject.caId()));
        Credential rawCredential;
        try {
            rawCredential = CredentialSnapshots.copy(backendCredential);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(), Optional.of(subject.caId()),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaCertificateMatches(rawCredential, issuerCredential, gated, subject.caId(), ISSUE_INT_REJECTED,
                BACKEND_CRED_MISMATCH);
        Credential cred = IssuerAuthorities.withIssuer(rawCredential,
                new IssuerRef(issuer.caId(), parentGeneration.issuerId(), parentPath.pathId()));
        store.putCredential(cred);
        IssuerGeneration subjectGeneration = IssuerAuthorities.generation(subject.caId(),
                subject.issuerKeyRef(), cred);
        IssuerChainPath subjectPath = IssuerAuthorities.childPath(subject.caId(),
                subjectGeneration.issuerId(), cred.credentialId(), parentPath);
        store.putIssuerGeneration(subjectGeneration);
        store.putIssuerChainPath(subjectPath);

        List<PkiId> updated = new ArrayList<>(subject.issuerIds());
        updated.add(subjectGeneration.issuerId());
        CaRecord updatedCa = new CaRecord(subject.caId(), subject.kind(), subject.state(), subject.issuerKeyRef(),
                subject.subjectRef(), List.copyOf(updated), subject.currentIssuanceIssuerId(),
                subject.issuanceChainPathId());
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
        return rolloverCaCertificate(command, CancellationSignal.NONE);
    }

    /**
     * Rolls over a CA credential, keeping the same key reference. Mints a new issuer
     * generation for the existing CA, advances the current issuance pointers to it,
     * and keeps historical generations for chain selection and validation of
     * previously issued credentials.
     */
    // The monitor serializes the complete read-renew-publish transition for one service instance.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    @Override
    public synchronized PkiId rolloverCaCertificate(CaRolloverCommand command, CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        Objects.requireNonNull(command, "command");
        CaRecord ca = getCa(command.caId());
        return renewCaGeneration(ca, command.issuerCaId(), ca.issuerKeyRef(), command.requestedValidity(),
                command.attributes(), cancellation);
    }

    /**
     * Requests CA key rotation.
     *
     * <p>
     * Rotation changes the CA key reference and issues a new corresponding CA
     * credential (a new issuer generation), then advances the current issuance
     * pointers and the CA key reference. Historical generations and key references
     * remain discoverable for audit and validation of previously issued
     * credentials. Key generation is not wired: {@code newKeyRef} is required.
     * </p>
     *
     * @param command key rotation request; must not be {@code null}
     * @return the CA identifier
     */
    @Override
    public PkiId rotateCaKey(CaKeyRotationCommand command) {
        return rotateCaKey(command, CancellationSignal.NONE);
    }

    // The monitor serializes the complete read-rotate-publish transition for one service instance.
    @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
    @Override
    public synchronized PkiId rotateCaKey(CaKeyRotationCommand command, CancellationSignal cancellation) {
        Objects.requireNonNull(cancellation, CANCELLATION_PARAMETER);
        Objects.requireNonNull(command, "command");
        KeyRef newKeyRef = command.newKeyRef()
                .orElseThrow(() -> new PkiException("CA key rotation requires newKeyRef (key generation not wired)"));
        CaRecord ca = getCa(command.caId());
        return renewCaGeneration(ca, command.issuerCaId(), newKeyRef, Optional.empty(), command.attributes(),
                cancellation);
    }

    // Shared rollover/rotation core: mints a new CA generation for the existing CA using the
    // supplied signing key, advances the current issuance pointers to it, and adopts the signing
    // key on the CA record. Rollover supplies the CA's existing key; rotation supplies a new key.
    // A root CA re-signs itself (issuerCaId empty); an intermediate CA is re-signed by its parent.
    private PkiId renewCaGeneration(CaRecord ca, Optional<PkiId> issuerCaId, KeyRef signingKey,
            Optional<Validity> requestedValidity, AttributeSet attributes,
            CancellationSignal cancellation) {
        ensureActive(ca, "subject");
        requireNoCaOverrides(attributes);
        CertificateProfileRef currentProfile = ((CaProfileBinding) IssuerAuthorities.currentCredential(store, ca)
                .profileBinding()).reference();
        ActiveCertificateProfile activeProfile = profileService.requireActiveProfile(currentProfile.profileId());
        IssuerGeneration generation;
        IssuerChainPath path;
        if (ca.kind() == CaKind.ROOT) {
            if (issuerCaId.isPresent()) {
                throw new PkiException("Root CA rollover is self-issued: issuerCaId must be empty");
            }
            CaCertificateProfileValidator.requireProfileShape(activeProfile, CertificateProfileKind.ROOT_CA,
                    framework.formatId());
            Credential credential = signRootGeneration(ca.caId(), ca.subjectRef(), signingKey, activeProfile,
                    requestedValidity, cancellation);
            generation = IssuerAuthorities.generation(ca.caId(), signingKey, credential);
            path = IssuerAuthorities.rootPath(ca.caId(), generation.issuerId(), credential.credentialId());
            store.putCredential(credential);
            store.putIssuerGeneration(generation);
            store.putIssuerChainPath(path);
        } else {
            PkiId parentId = issuerCaId
                    .orElseThrow(() -> new PkiException("Intermediate CA rollover requires issuerCaId"));
            CaRecord issuer = getCa(parentId);
            ensureActive(issuer, "issuer");
            CaCertificateProfileValidator.requireProfileShape(activeProfile, CertificateProfileKind.INTERMEDIATE_CA,
                    framework.formatId());
            RenewedIntermediate renewed = signIntermediateGeneration(ca, issuer, signingKey, requestedValidity,
                    activeProfile, cancellation);
            store.putCredential(renewed.credential());
            generation = IssuerAuthorities.generation(ca.caId(), signingKey, renewed.credential());
            path = IssuerAuthorities.childPath(ca.caId(), generation.issuerId(), renewed.credential().credentialId(),
                    renewed.parentPath());
            store.putIssuerGeneration(generation);
            store.putIssuerChainPath(path);
        }
        publishRenewedCa(ca, generation, path, signingKey);
        return ca.caId();
    }

    // Advances the current issuance pointers to the new generation/path and adopts the signing
    // key, appending the new generation to the CA's ordered history. This pointer advance is the
    // single commit point of a rollover/rotation and is deliberately performed last.
    private void publishRenewedCa(CaRecord ca, IssuerGeneration generation, IssuerChainPath path, KeyRef signingKey) {
        List<PkiId> issuerIds = new ArrayList<>(ca.issuerIds());
        if (!issuerIds.contains(generation.issuerId())) {
            issuerIds.add(generation.issuerId());
        }
        store.putCa(new CaRecord(ca.caId(), ca.kind(), ca.state(), signingKey, ca.subjectRef(),
                List.copyOf(issuerIds), generation.issuerId(), path.pathId()));
    }

    private Credential signRootGeneration(PkiId caId, SubjectRef subjectRef, KeyRef keyRef,
            ActiveCertificateProfile activeProfile, Optional<Validity> requestedValidity,
            CancellationSignal cancellation) {
        Instant evaluationTime = clock.instant();
        EncodedObject spki = proofGate.resolveManagedKey(keyRef, framework.formatId(), CREATE_ROOT_REJECTED,
                Optional.empty());
        BigInteger serial = CertificateSerialAllocator.allocate();
        ValidatedCaCertificateRequest request = CaCertificateProfileValidator.validate(
                ValidatedCaCertificateRequest.Operation.CREATE_ROOT, activeProfile, CertificateProfileKind.ROOT_CA,
                framework.formatId(), caId, caId, subjectRef, spki, requestedValidity, evaluationTime,
                Optional.empty(), serial, authority);
        byte[] rootPublicKeyInfo = proofGate.parseRootSpki(spki, framework.formatId());
        CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(keyRef, framework.formatId(),
                CREATE_ROOT_REJECTED, Optional.empty(), cancellation);
        requireSameManagedKey(spki, proof.exactPublicKey(), CREATE_ROOT_REJECTED, framework.formatId(),
                Optional.empty());
        Validity validity = request.validity();
        X500Principal dn = zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport.subject(request.subjectRdns());
        CertificateBuilder b = Pkix.certificateBuilder().issuer(dn).serialNumber(serial)
                .validity(validity.notBefore(), validity.notAfter()).subject(dn).publicKeyInfo(rootPublicKeyInfo);
        try {
            b.basicConstraints(BasicConstraints.ca(request.policy().pathLengthConstraint()),
                    request.policy().basicConstraintsCritical());
            b.keyUsage(java.util.EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN),
                    request.policy().keyUsageCritical());
        } catch (Exception ex) {
            throw new PkiException("Root extension construction failed: code=ROOT_EXTENSION_BUILD_FAILED");
        }
        // ROLLOVER_ROOT continuation mirrors CREATE_ROOT (fields 0-12) and freezes the existing
        // authority id in field 13, so an async/remote signature is durably resumable and publishes a
        // new generation for the existing CA (with pointer advance) on reconcile.
        DomainContinuationTemplate domain = DomainCommandEncoding.template(DomainContinuationStore.Kind.CA,
                "ROLLOVER_ROOT", framework.formatId().value(), request.subjectRef().value(),
                request.profileReference().profileId(), keyRef.value(), request.profileReference().profileId(),
                Long.toString(request.profileReference().profileVersion()),
                HexFormat.of().formatHex(request.profileReference().canonicalSha256()),
                validity.notBefore().toString(), validity.notAfter().toString(), serial.toString(),
                request.subjectRdns().toString(), request.policy().toString(),
                request.algorithmBindingPolicy().toString(), caId.value());
        X509Certificate cert;
        try (PkiBusContentSigner signer = proofGate.signer(proof, request.algorithmBindingPolicy(), cancellation,
                domain)) {
            cert = b.build(signer);
        } catch (PendingSigningOperation | SigningExecutionException signingFailure) {
            throw signingFailure;
        } catch (RuntimeException ex) { // NOPMD - redacted signing failure
            throw proofGate.rejection(CREATE_ROOT_REJECTED, framework.formatId(), Optional.empty(),
                    "ROOT_SIGNING_FAILED");
        }
        if (!proofGate.rootProofIsValid(cert, spki)) {
            throw proofGate.rejection(CREATE_ROOT_REJECTED, framework.formatId(), Optional.empty(),
                    "ROOT_SELF_SIGNATURE_INVALID");
        }
        byte[] certDer;
        try {
            certDer = cert.getEncoded();
        } catch (Exception ex) {
            throw new PkiException("Root certificate encoding failed: code=ROOT_CERTIFICATE_ENCODE_FAILED");
        }
        PkiId credId = new PkiId("x509:" + sha256Hex(certDer));
        PkiId issuerId = IssuerGeneration.idFor(caId, credId);
        IssuerChainPath rootPath = IssuerAuthorities.rootPath(caId, issuerId, credId);
        Credential credential = new Credential(credId, framework.formatId(),
                new IssuerRef(caId, issuerId, rootPath.pathId()), request.subjectRef(), validity, serial.toString(),
                new PkiId("spki:" + sha256Hex(spki.bytes())), new CaProfileBinding(request.profileReference()),
                CredentialStatus.ISSUED, CredentialContent.stage(store, certDer), SimpleAttributeSet.builder().build());
        CredentialProfileBindings.requireCaBinding(credential.profileBinding(), request.profileReference());
        requireCaCertificateMatches(credential, credential, request, caId, CREATE_ROOT_REJECTED, BACKEND_CRED_MISMATCH);
        return credential;
    }

    private RenewedIntermediate signIntermediateGeneration(CaRecord subject, CaRecord issuer, KeyRef subjectKey,
            Optional<Validity> requestedValidity, ActiveCertificateProfile activeProfile,
            CancellationSignal cancellation) {
        Instant evaluationTime = clock.instant();
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCredential = CredentialSnapshots.copy(selectIssuerCredential(issuer, framework.formatId(),
                CredentialUse.INTERMEDIATE_ISSUER, statusEvaluation));
        IssuerGeneration parentGeneration = IssuerAuthorities.current(store, issuer);
        IssuerChainPath parentPath = IssuerAuthorities.issuancePath(store, issuer);
        requireHistoricalCaProfile(issuerCredential,
                issuer.kind() == CaKind.ROOT ? CertificateProfileKind.ROOT_CA : CertificateProfileKind.INTERMEDIATE_CA);
        List<zeroecho.pki.api.request.SubjectRdn> approvedSubject = CaCertificateProfileValidator
                .validateTrustedSubject(subject.subjectRef(), activeProfile.definition());
        EncodedObject subjectSpki = proofGate.resolveManagedKey(subjectKey, framework.formatId(), ISSUE_INT_REJECTED,
                Optional.of(subject.caId()));
        ValidatedCaCertificateRequest gated = CaCertificateProfileValidator.validateApprovedSubject(
                ValidatedCaCertificateRequest.Operation.ROLLOVER_INTERMEDIATE, activeProfile,
                CertificateProfileKind.INTERMEDIATE_CA, framework.formatId(), issuer.caId(), subject.caId(),
                approvedSubject, subjectSpki, requestedValidity, evaluationTime,
                Optional.of(issuerCredential.validity().notAfter()), CertificateSerialAllocator.allocate(), authority);
        gated = gated.withFrozenPublication(parentGeneration.issuerId(), parentPath.pathId(),
                parentPath.pathCommitment(), subjectKey);
        CaProofGate.ManagedKeyProof subjectProof = proofGate.proveManagedKey(subjectKey, framework.formatId(),
                ISSUE_INT_REJECTED, Optional.of(subject.caId()), cancellation);
        requireSameManagedKey(subjectSpki, subjectProof.exactPublicKey(), ISSUE_INT_REJECTED, framework.formatId(),
                Optional.of(subject.caId()));
        requireIssuerKeyBinding(issuer, issuerCredential, framework.formatId(), ISSUE_INT_REJECTED,
                Optional.of(subject.caId()), cancellation);
        Credential backendCredential;
        try {
            backendCredential = issuerBackend.issueIntermediateCertificate(gated, issuerCredential.content(),
                    issuer.issuerKeyRef(), cancellation);
        } catch (PendingSigningOperation | SigningExecutionException signingFailure) {
            throw signingFailure;
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(ISSUE_INT_REJECTED, framework.formatId(), Optional.of(subject.caId()),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaBinding(backendCredential, gated.profileReference(), ISSUE_INT_REJECTED, framework.formatId(),
                Optional.of(subject.caId()));
        Credential rawCredential;
        try {
            rawCredential = CredentialSnapshots.copy(backendCredential);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(ISSUE_INT_REJECTED, framework.formatId(), Optional.of(subject.caId()),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaCertificateMatches(rawCredential, issuerCredential, gated, subject.caId(), ISSUE_INT_REJECTED,
                BACKEND_CRED_MISMATCH);
        Credential cred = IssuerAuthorities.withIssuer(rawCredential,
                new IssuerRef(issuer.caId(), parentGeneration.issuerId(), parentPath.pathId()));
        return new RenewedIntermediate(cred, parentPath);
    }

    private record RenewedIntermediate(Credential credential, IssuerChainPath parentPath) {
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
                existing.subjectRef(), existing.issuerIds(), existing.currentIssuanceIssuerId(),
                existing.issuanceChainPathId());
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
        return store.getCa(caId).orElseThrow(() -> new PkiException("CA not found",
                zeroecho.pki.api.PkiFailureReason.ISSUER_CA_NOT_FOUND));
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
                Credential current = IssuerAuthorities.currentCredential(store, r);
                return query.formatId().get().equals(current.formatId());
            }
            return true;
        }).toList();
    }

    @Override
    public IssuerGeneration getIssuerGeneration(PkiId issuerId) {
        Objects.requireNonNull(issuerId, "issuerId");
        return store.getIssuerGeneration(issuerId).orElseThrow(() -> new PkiException("Issuer generation not found",
                zeroecho.pki.api.PkiFailureReason.ISSUER_GENERATION_NOT_FOUND));
    }

    @Override
    public IssuerChainPath getIssuerChainPath(PkiId pathId) {
        Objects.requireNonNull(pathId, "pathId");
        return store.getIssuerChainPath(pathId).orElseThrow(() -> new PkiException("Issuer chain path not found",
                zeroecho.pki.api.PkiFailureReason.ISSUER_CHAIN_PATH_NOT_FOUND));
    }

    @Override
    public List<IssuerChainPath> listIssuerChainPaths(PkiId issuerId) {
        return store.listIssuerChainPaths(Objects.requireNonNull(issuerId, "issuerId"));
    }

    @Override
    public void selectIssuancePath(PkiId caId, PkiId issuerId, PkiId pathId, String reason) {
        Objects.requireNonNull(caId, "caId");
        Objects.requireNonNull(issuerId, "issuerId");
        Objects.requireNonNull(pathId, "pathId");
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be null/blank");
        }
        CaRecord ca = getCa(caId);
        IssuerGeneration generation = getIssuerGeneration(issuerId);
        IssuerChainPath path = getIssuerChainPath(pathId);
        if (!ca.issuerIds().contains(issuerId) || !caId.equals(generation.authorityId())
                || generation.state() != zeroecho.pki.api.ca.IssuerGenerationState.ACTIVE
                || !caId.equals(path.authorityId()) || !issuerId.equals(path.issuerId())) {
            throw new PkiException("Issuance selection is outside the authority");
        }
        store.putCa(new CaRecord(ca.caId(), ca.kind(), ca.state(), ca.issuerKeyRef(), ca.subjectRef(),
                ca.issuerIds(), issuerId, pathId));
    }

    @Override
    public IssuerChainPath registerIssuerChainPath(PkiId caId, PkiId issuerId,
            PkiId parentPathId) {
        CaRecord ca = getCa(Objects.requireNonNull(caId, "caId"));
        IssuerGeneration generation = getIssuerGeneration(
                Objects.requireNonNull(issuerId, "issuerId"));
        IssuerChainPath parent = getIssuerChainPath(
                Objects.requireNonNull(parentPathId, "parentPathId"));
        if (!ca.issuerIds().contains(issuerId) || !caId.equals(generation.authorityId())) {
            throw new PkiException("Issuer generation is outside the authority");
        }
        IssuerChainPath path = IssuerAuthorities.childPath(caId, issuerId,
                generation.credentialId(), parent);
        store.putIssuerChainPath(path);
        return path;
    }

    private static void ensureActive(CaRecord ca, String role) {
        if (ca.state() != CaState.ACTIVE) {
            throw new PkiException("CA not ACTIVE: " + role,
                    zeroecho.pki.api.PkiFailureReason.ISSUER_CA_NOT_ACTIVE);
        }
    }

    private Credential selectIssuerCredential(CaRecord issuer, FormatId formatId, CredentialUse use,
            EffectiveCredentialStatusResolver.Evaluation evaluation) {
        Credential credential = IssuerAuthorities.currentCredential(store, issuer);
        if (!formatId.equals(credential.formatId())) {
            throw new PkiException("Issuer credential unavailable: code=ISSUER_CREDENTIAL_UNAVAILABLE");
        }
        EffectiveCredentialStatus status = evaluation.resolve(credential);
        if (status != EffectiveCredentialStatus.USABLE) {
            CredentialTrustAudit.rejected(auditSink, evaluation.evaluationTime(), credential, use,
                    "ISSUER_CREDENTIAL_UNAVAILABLE", status);
            throw new PkiException("Issuer credential unavailable: code=ISSUER_CREDENTIAL_UNAVAILABLE");
        }
        return credential;
    }

    private void requireValidImportedRoot(CaImportCommand command, X509Certificate holder,
            CancellationSignal cancellation) {
        try {
            CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(command.keyRef(), command.formatId(),
                    IMPORT_ROOT_REJECTED, Optional.empty(), cancellation);
            if (!MessageDigest.isEqual(proof.exactPublicKey().bytes(), Pkix.subjectPublicKeyInfo(holder))) {
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
            Optional<PkiId> objectId, CancellationSignal cancellation) {
        try {
            if (credential.content().encoding() != Encoding.DER) {
                throw proofGate.rejection(action, formatId, objectId, "ISSUER_CREDENTIAL_INVALID");
            }
            CredentialContent.validateCertificate(store, credential.content(), authority, Optional.empty());
            X509Certificate holder = Pkix.parseCertificate(CredentialContent.materializeForBc(store,
                    credential.content()));
            CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(issuer.issuerKeyRef(), formatId, action,
                    objectId, cancellation);
            if (!MessageDigest.isEqual(proof.exactPublicKey().bytes(), Pkix.subjectPublicKeyInfo(holder))) {
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
                throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId), mismatchCode);
            }
            CredentialContent.validateCertificate(store, credential.content(), authority,
                    Optional.of(signatureIdentity));
            CredentialContent.validateCertificate(store, issuerCredential.content(), authority, Optional.empty());
            byte[] credentialDer = CredentialContent.materializeForBc(store, credential.content());
            X509Certificate holder = Pkix.parseCertificate(credentialDer);
            X509Certificate issuerHolder = Pkix.parseCertificate(CredentialContent.materializeForBc(store,
                    issuerCredential.content()));
            byte[] actualSpki = Pkix.subjectPublicKeyInfo(holder);
            X500Principal expectedSubject = zeroecho.pki.impl.framework.x509.bc.BcX509ProfileSupport
                    .subject(request.subjectRdns());
            X500Principal expectedIssuer = request.certificateType() == CertificateProfileKind.ROOT_CA ? expectedSubject
                    : issuerHolder.getSubjectX500Principal();
            if (!matchesCaCertificateIdentity(holder, issuerHolder, request, expectedSubject, expectedIssuer,
                    actualSpki)
                    || !matchesCaCertificatePolicy(holder, request)
                    || !matchesCaCredentialMetadata(credential, holder, request, actualSpki, credentialDer)) {
                throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId), mismatchCode);
            }
            CredentialProfileBindings.requireCaBinding(credential.profileBinding(), request.profileReference());
        } catch (PkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId), mismatchCode);
        }
    }

    private boolean matchesCaCredentialEnvelope(Credential credential, ValidatedCaCertificateRequest request,
            PkiId subjectCaId) {
        return framework.formatId().equals(credential.formatId()) && credential.content().encoding() == Encoding.DER
                && credential.status() == CredentialStatus.ISSUED
                && credential.subjectRef().equals(request.subjectRef())
                && credential.issuerRef().caId()
                        .equals(request.certificateType() == CertificateProfileKind.ROOT_CA ? subjectCaId
                                : request.issuerCaId());
    }

    private static boolean matchesCaCertificateIdentity(X509Certificate holder,
            X509Certificate issuerHolder, ValidatedCaCertificateRequest request, X500Principal expectedSubject,
            X500Principal expectedIssuer, byte[] actualSpki) {
        return MessageDigest.isEqual(request.exactPublicKey().bytes(), actualSpki)
                && MessageDigest.isEqual(holder.getSubjectX500Principal().getEncoded(), expectedSubject.getEncoded())
                && MessageDigest.isEqual(holder.getIssuerX500Principal().getEncoded(), expectedIssuer.getEncoded())
                && signatureValid(holder, issuerHolder.getPublicKey());
    }

    private static boolean signatureValid(X509Certificate certificate, java.security.PublicKey signerKey) {
        try {
            certificate.verify(signerKey);
            return true;
        } catch (java.security.GeneralSecurityException failure) {
            return false;
        }
    }

    // Dotted literals are X.509 extension object identifiers, not network addresses.
    @SuppressWarnings("PMD.AvoidUsingHardCodedIP")
    private static boolean matchesCaCertificatePolicy(X509Certificate holder,
            ValidatedCaCertificateRequest request) {
        int basicConstraints = holder.getBasicConstraints();
        boolean[] keyUsage = holder.getKeyUsage();
        int extensionCount = extensionOidCount(holder);
        return isCritical(holder, "2.5.29.19") && basicConstraints != -1
                && basicConstraints == request.policy().pathLengthConstraint()
                && keyUsage != null && isCritical(holder, "2.5.29.15") && hasIntermediateKeyUsage(keyUsage)
                && extensionCount == 2;
    }

    private static boolean isCritical(X509Certificate certificate, String oid) {
        java.util.Set<String> critical = certificate.getCriticalExtensionOIDs();
        return critical != null && critical.contains(oid);
    }

    private static int extensionOidCount(X509Certificate certificate) {
        java.util.Set<String> all = new java.util.HashSet<>();
        if (certificate.getCriticalExtensionOIDs() != null) {
            all.addAll(certificate.getCriticalExtensionOIDs());
        }
        if (certificate.getNonCriticalExtensionOIDs() != null) {
            all.addAll(certificate.getNonCriticalExtensionOIDs());
        }
        return all.size();
    }

    private static boolean matchesCaCredentialMetadata(Credential credential, X509Certificate holder,
            ValidatedCaCertificateRequest request, byte[] actualSpki, byte[] credentialDer) {
        return credential.publicKeyId().equals(new PkiId("spki:" + sha256Hex(actualSpki)))
                && credential.credentialId().equals(new PkiId("x509:" + sha256Hex(credentialDer)))
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
            CertificateProfileRef expectedCaProfile, String action, FormatId formatId,
            Optional<PkiId> objectId) {
        try {
            CredentialProfileBindings.requireCaBinding(credential == null ? null : credential.profileBinding(),
                    expectedCaProfile);
        } catch (PkiException mismatch) {
            throw proofGate.rejection(action, formatId, objectId, CredentialProfileBindings.MISMATCH_CODE);
        }
    }

    // The boolean array is the fixed X.509 keyUsage bitmap, not a variable argument sequence.
    @SuppressWarnings("PMD.UseVarargs")
    private static boolean hasIntermediateKeyUsage(boolean[] keyUsage) {
        if (!bit(keyUsage, 5) || !bit(keyUsage, 6)) {
            return false;
        }
        return !bit(keyUsage, 0) && !bit(keyUsage, 1) && !bit(keyUsage, 2) && !bit(keyUsage, 3)
                && !bit(keyUsage, 4) && !bit(keyUsage, 7) && !bit(keyUsage, 8);
    }

    private static boolean bit(boolean[] keyUsage, int index) {
        return keyUsage != null && index < keyUsage.length && keyUsage[index];
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
        CertificateProfileRef reference = binding.reference();
        zeroecho.pki.api.profile.ImportedCertificateProfileVersion version = profileService
                .getImportedVersion(reference.profileId(), reference.profileVersion())
                .orElseThrow(() -> new PkiException("CA issuer profile rejected: code=CA_PROFILE_VERSION_MISSING"));
        if (!version.reference().equals(reference) || version.definition().certificateType() != expectedKind
                || !version.definition().formatId().equals(credential.formatId())
                || !credential.formatId().equals(framework.formatId())) {
            throw new PkiException("CA issuer profile rejected: code=CA_PROFILE_REFERENCE_MISMATCH");
        }
    }

    private void requireSameManagedKey(EncodedObject expected, EncodedObject actual, String action, FormatId formatId,
            Optional<PkiId> objectId) {
        if (expected.encoding() != actual.encoding() || !MessageDigest.isEqual(expected.bytes(), actual.bytes())) {
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
