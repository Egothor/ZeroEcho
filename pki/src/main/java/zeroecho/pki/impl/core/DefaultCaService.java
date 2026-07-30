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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
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
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.CredentialUse;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.impl.framework.x509.bc.BcX509Attributes;
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
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.PreserveStackTrace" })
public final class DefaultCaService implements CaService {

    private static final Logger LOG = Logger.getLogger(DefaultCaService.class.getName());
    private static final String CREATE_INT_REJECTED = "CREATE_INTERMEDIATE_REJECTED";
    private static final String ISSUE_INT_REJECTED = "ISSUE_INTERMEDIATE_REJECTED";
    private static final String BACKEND_CRED_MISMATCH = "BACKEND_CREDENTIAL_MISMATCH";

    private final PkiStore store;
    private final CredentialFramework framework;
    private final CredentialIssuerBackend issuerBackend;
    private final CaProofGate proofGate;
    private final AuditSink auditSink;
    private final EffectiveCredentialStatusResolver statusResolver;

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
            EffectiveCredentialStatusResolver statusResolver, String signatureAlgorithmId, Duration signingTtl) {

        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
        this.issuerBackend = Objects.requireNonNull(issuerBackend, "issuerBackend");
        Objects.requireNonNull(publicKeyResolver, "publicKeyResolver");
        Objects.requireNonNull(signingBus, "signingBus");
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.statusResolver = Objects.requireNonNull(statusResolver, "statusResolver");
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
        if (command.keyRef().isEmpty()) {
            throw new PkiException("Root CA creation requires keyRef (key generation not wired)");
        }
        if (!framework.formatId().equals(command.formatId())) {
            throw new PkiException("Unsupported formatId for this runtime");
        }
        KeyRef keyRef = command.keyRef().get();

        SubjectRef subjectRef = command.subjectRef();
        CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(keyRef, command.formatId(),
                "CREATE_ROOT_REJECTED", Optional.empty());
        EncodedObject spki = proof.exactPublicKey();
        SubjectPublicKeyInfo rootPublicKeyInfo = proofGate.parseRootSpki(spki, command.formatId());

        Instant now = Instant.now();
        Validity validity = new Validity(now.minus(Duration.ofMinutes(1)), now.plus(Duration.ofDays(3650)));
        X500Name dn = new X500Name(subjectRef.value());

        BigInteger serial = BigInteger.valueOf(Math.abs(now.toEpochMilli()) + 1L);
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(dn, serial, Date.from(validity.notBefore()),
                Date.from(validity.notAfter()), dn, rootPublicKeyInfo);
        try {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } catch (Exception ex) {
            throw new PkiException("Root extension construction failed: code=ROOT_EXTENSION_BUILD_FAILED");
        }

        ContentSigner signer = proofGate.signer(proof);
        X509CertificateHolder cert;
        try {
            cert = b.build(signer);
        } catch (RuntimeException ex) { // NOPMD
            throw proofGate.rejection("CREATE_ROOT_REJECTED", command.formatId(), Optional.empty(),
                    "ROOT_SIGNING_FAILED");
        }

        if (!proofGate.rootProofIsValid(cert, spki)) {
            throw proofGate.rejection("CREATE_ROOT_REJECTED", command.formatId(), Optional.empty(),
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

        Credential credential = new Credential(credId, command.formatId(), new IssuerRef(caId), subjectRef, validity,
                serial.toString(), publicKeyId, new CaProfileBinding(command.profileId()), CredentialStatus.ISSUED,
                new EncodedObject(Encoding.DER, certDer), command.attributes());
        CredentialProfileBindings.requireCaBinding(credential.profileBinding(), command.profileId());

        CaRecord ca = new CaRecord(caId, CaKind.ROOT, CaState.ACTIVE, keyRef, subjectRef, List.of(credential));
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

        requireValidImportedRoot(command, holder);

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
        Credential credential = new Credential(credId, command.formatId(), new IssuerRef(caId), command.subjectRef(),
                validity, serial.toString(), publicKeyId, new CaProfileBinding(command.profileId()),
                CredentialStatus.ISSUED,
                new EncodedObject(Encoding.DER, certDer), command.attributes());
        CredentialProfileBindings.requireCaBinding(credential.profileBinding(), command.profileId());
        store.putCredential(credential);
        CaRecord ca = new CaRecord(caId, CaKind.ROOT, CaState.ACTIVE, command.keyRef(), command.subjectRef(),
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
        if (command.keyRef().isEmpty()) {
            throw new PkiException("Intermediate creation requires keyRef (key generation not wired)");
        }

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

        PkiId caId = new PkiId("ca:" + sha256Hex((issuer.caId().value() + "\n" + command.subjectRef().value())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0, 16));

        CaProofGate.ManagedKeyProof subjectProof = proofGate.proveManagedKey(command.keyRef().get(),
                command.formatId(), CREATE_INT_REJECTED, Optional.of(caId));
        EncodedObject subjectSpki = subjectProof.exactPublicKey();
        requireIssuerKeyBinding(issuer, issuerCredential, command.formatId(), CREATE_INT_REJECTED,
                Optional.of(caId));
        AttributeSet authoritative = authoritativeIntermediateAttributes(command.attributes(), issuer,
                issuerCredential, subjectSpki, command.subjectRef());
        ManagedCaIssuance issue = proofGate.authorizeIntermediate(subjectProof,
                ManagedCaIssuance.Operation.CREATE_INTERMEDIATE, command.issuerCaId(), caId, command.profileId(),
                Optional.empty(), authoritative, command.subjectRef());

        Credential backendCredential;
        try {
            backendCredential = issuerBackend.issueIntermediateCertificate(issue);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(CREATE_INT_REJECTED, command.formatId(), Optional.of(caId),
                    BACKEND_CRED_MISMATCH);
        }
        requireCaBinding(backendCredential, command.profileId(), CREATE_INT_REJECTED,
                command.formatId(), Optional.of(caId));
        Credential cred;
        try {
            cred = CredentialSnapshots.copy(backendCredential);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(CREATE_INT_REJECTED, command.formatId(), Optional.of(caId),
                    BACKEND_CRED_MISMATCH);
        }
        requireIntermediateCredentialMatches(cred, issuerCredential, subjectSpki, command.subjectRef(),
                command.issuerCaId(), caId, CREATE_INT_REJECTED);
        store.putCredential(cred);

        CaRecord subject = new CaRecord(caId, CaKind.INTERMEDIATE, CaState.ACTIVE, command.keyRef().get(),
                command.subjectRef(), List.of(cred));
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
        CaRecord issuer = getCa(command.issuerCaId());
        ensureActive(issuer, "issuer");
        CaRecord subject = getCa(command.subjectCaId());
        ensureActive(subject, "subject");
        if (!framework.formatId().equals(command.formatId())) {
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(),
                    Optional.of(subject.caId()),
                    "FORMAT_UNSUPPORTED");
        }
        EffectiveCredentialStatusResolver.Evaluation statusEvaluation = statusResolver.beginEvaluation();
        Credential issuerCredential = CredentialSnapshots.copy(selectIssuerCredential(issuer, command.formatId(),
                CredentialUse.INTERMEDIATE_ISSUER, statusEvaluation));

        CaProofGate.ManagedKeyProof subjectProof = proofGate.proveManagedKey(subject.issuerKeyRef(),
                command.formatId(), ISSUE_INT_REJECTED, Optional.of(subject.caId()));
        EncodedObject subjectSpki = subjectProof.exactPublicKey();
        requireIssuerKeyBinding(issuer, issuerCredential, command.formatId(), ISSUE_INT_REJECTED,
                Optional.of(subject.caId()));
        AttributeSet authoritative = authoritativeIntermediateAttributes(command.attributes(), issuer,
                issuerCredential, subjectSpki, subject.subjectRef());
        ManagedCaIssuance gated = proofGate.authorizeIntermediate(subjectProof,
                ManagedCaIssuance.Operation.ISSUE_INTERMEDIATE, command.issuerCaId(), command.subjectCaId(),
                command.profileId(), command.requestedValidity(), authoritative, subject.subjectRef());

        Credential backendCredential;
        try {
            backendCredential = issuerBackend.issueIntermediateCertificate(gated);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(),
                    Optional.of(subject.caId()), BACKEND_CRED_MISMATCH);
        }
        requireCaBinding(backendCredential, command.profileId(), ISSUE_INT_REJECTED,
                command.formatId(), Optional.of(subject.caId()));
        Credential cred;
        try {
            cred = CredentialSnapshots.copy(backendCredential);
        } catch (RuntimeException ex) { // NOPMD - reject malformed or mutable framework output
            throw proofGate.rejection(ISSUE_INT_REJECTED, command.formatId(),
                    Optional.of(subject.caId()), BACKEND_CRED_MISMATCH);
        }
        requireIntermediateCredentialMatches(cred, issuerCredential, subjectSpki, subject.subjectRef(),
                command.issuerCaId(), subject.caId(), ISSUE_INT_REJECTED);
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
            BasicConstraints constraints = BasicConstraints
                    .getInstance(holder.getExtension(Extension.basicConstraints).getParsedValue());
            if (!holder.getSubject().equals(holder.getIssuer()) || !constraints.isCA()
                    || !holder.getSubject().equals(new X500Name(command.subjectRef().value()))
                    || !holder.isSignatureValid(
                            new JcaContentVerifierProviderBuilder().build(holder.getSubjectPublicKeyInfo()))) {
                throw proofGate.rejection("IMPORT_ROOT_REJECTED", command.formatId(), Optional.empty(),
                        "ROOT_CREDENTIAL_INVALID");
            }
            CaProofGate.ManagedKeyProof proof = proofGate.proveManagedKey(command.keyRef(), command.formatId(),
                    "IMPORT_ROOT_REJECTED", Optional.empty());
            if (!MessageDigest.isEqual(proof.exactPublicKey().bytes(), holder.getSubjectPublicKeyInfo().getEncoded())) {
                throw proofGate.rejection("IMPORT_ROOT_REJECTED", command.formatId(), Optional.empty(),
                        "ROOT_MANAGED_KEY_MISMATCH");
            }
        } catch (PkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw proofGate.rejection("IMPORT_ROOT_REJECTED", command.formatId(), Optional.empty(),
                    "ROOT_CREDENTIAL_INVALID");
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

    private void requireIntermediateCredentialMatches(Credential credential, Credential issuerCredential,
            EncodedObject exactSubjectSpki, SubjectRef subjectRef, PkiId issuerCaId, PkiId subjectCaId,
            String action) {
        try {
            if (!framework.formatId().equals(credential.formatId())
                    || credential.encoded().encoding() != Encoding.DER
                    || credential.status() != CredentialStatus.ISSUED
                    || !credential.subjectRef().equals(subjectRef)
                    || !credential.issuerRef().equals(new IssuerRef(issuerCaId))) {
                throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId),
                        BACKEND_CRED_MISMATCH);
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
            if (!MessageDigest.isEqual(exactSubjectSpki.bytes(), actualSpki)
                    || !holder.getSubject().equals(new X500Name(subjectRef.value()))
                    || !holder.getIssuer().equals(issuerHolder.getSubject())
                    || !holder.isSignatureValid(
                            new JcaContentVerifierProviderBuilder().build(issuerHolder.getSubjectPublicKeyInfo()))
                    || constraintsExtension == null || !constraintsExtension.isCritical()
                    || constraints == null || !constraints.isCA()
                    || !BigInteger.ZERO.equals(constraints.getPathLenConstraint())
                    || keyUsageExtension == null || !keyUsageExtension.isCritical()
                    || !hasIntermediateKeyUsage(keyUsage)
                    || !credential.publicKeyId().equals(new PkiId("spki:" + sha256Hex(actualSpki)))
                    || !credential.credentialId()
                            .equals(new PkiId("x509:" + sha256Hex(credential.encoded().bytes())))
                    || !credential.serialOrUniqueId().equals(holder.getSerialNumber().toString())
                    || credential.validity().notBefore().getEpochSecond() != holder.getNotBefore().toInstant()
                            .getEpochSecond()
                    || credential.validity().notAfter().getEpochSecond() != holder.getNotAfter().toInstant()
                            .getEpochSecond()) {
                throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId),
                        BACKEND_CRED_MISMATCH);
            }
        } catch (PkiException ex) {
            throw ex;
        } catch (Exception ex) {
            throw proofGate.rejection(action, framework.formatId(), Optional.of(subjectCaId),
                    BACKEND_CRED_MISMATCH);
        }
    }

    private void requireCaBinding(Credential credential, String expectedCaProfileId, String action,
            FormatId formatId, Optional<PkiId> objectId) {
        try {
            CredentialProfileBindings.requireCaBinding(
                    credential == null ? null : credential.profileBinding(), expectedCaProfileId);
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

    private static AttributeSet authoritativeIntermediateAttributes(AttributeSet callerAttributes, CaRecord issuer,
            Credential issuerCredential, EncodedObject subjectSpki, SubjectRef subjectRef) {
        SimpleAttributeSet.Builder builder = SimpleAttributeSet.builder().putAll(callerAttributes);
        builder.put(BcX509Attributes.ISSUER_CERT_DER,
                new AttributeValue.BytesValue(issuerCredential.encoded().bytes().clone()));
        builder.put(BcX509Attributes.ISSUER_KEYREF, new AttributeValue.StringValue(issuer.issuerKeyRef().value()));
        builder.put(BcX509Attributes.SUBJECT_SPKI_DER,
                new AttributeValue.BytesValue(subjectSpki.bytes().clone()));
        builder.put(BcX509Attributes.SUBJECT_DN, new AttributeValue.StringValue(subjectRef.value()));
        return builder.build();
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
