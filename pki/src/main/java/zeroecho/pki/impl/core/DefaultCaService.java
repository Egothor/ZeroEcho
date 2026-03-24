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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
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
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.spi.framework.CredentialFramework;
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
public final class DefaultCaService implements CaService {

    private static final Logger LOG = Logger.getLogger(DefaultCaService.class.getName());

    private final PkiStore store;
    private final CredentialFramework framework;
    private final PublicKeyInfoResolver publicKeyResolver;
    private final PkiSigningBus signingBus;
    private final String signatureAlgorithmId;
    private final Duration signingTtl;

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
     * @param publicKeyResolver    resolver used to obtain subject public key
     *                             material in SPKI DER form for key references;
     *                             must not be {@code null}
     * @param signingBus           signing orchestration component used to request
     *                             delegated signing operations; must not be
     *                             {@code null}
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
    public DefaultCaService(PkiStore store, CredentialFramework framework, PublicKeyInfoResolver publicKeyResolver,
            PkiSigningBus signingBus, String signatureAlgorithmId, Duration signingTtl) {

        this.store = Objects.requireNonNull(store, "store");
        this.framework = Objects.requireNonNull(framework, "framework");
        this.publicKeyResolver = Objects.requireNonNull(publicKeyResolver, "publicKeyResolver");
        this.signingBus = Objects.requireNonNull(signingBus, "signingBus");
        if (signatureAlgorithmId == null || signatureAlgorithmId.isBlank()) {
            throw new IllegalArgumentException("signatureAlgorithmId must not be null/blank");
        }
        if (signingTtl == null || signingTtl.isZero() || signingTtl.isNegative()) {
            throw new IllegalArgumentException("signingTtl must be positive");
        }
        this.signatureAlgorithmId = signatureAlgorithmId;
        this.signingTtl = signingTtl;
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
        EncodedObject spki = publicKeyResolver.resolveSpkiDer(keyRef);

        Instant now = Instant.now();
        Validity validity = new Validity(now.minus(Duration.ofMinutes(1)), now.plus(Duration.ofDays(3650)));
        X500Name dn = new X500Name(subjectRef.value());

        BigInteger serial = BigInteger.valueOf(Math.abs(now.toEpochMilli()) + 1L);
        X509v3CertificateBuilder b = new X509v3CertificateBuilder(dn, serial, Date.from(validity.notBefore()),
                Date.from(validity.notAfter()), dn,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(spki.bytes()));
        try {
            b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } catch (Exception ex) {
            throw new PkiException("Failed to build root certificate extensions", ex);
        }

        ContentSigner signer = new BusBackedContentSigner(signingBus, keyRef, signatureAlgorithmId, signingTtl);
        X509CertificateHolder cert;
        try {
            cert = b.build(signer);
        } catch (RuntimeException ex) { // NOPMD
            throw new PkiException("Root certificate signing failed", ex);
        }

        byte[] certDer;
        try {
            certDer = cert.getEncoded();
        } catch (Exception ex) {
            throw new PkiException("Root certificate encoding failed", ex);
        }

        PkiId credId = new PkiId("x509:" + sha256Hex(certDer));
        PkiId caId = new PkiId("ca:" + sha256Hex(certDer).substring(0, 16));

        PkiId publicKeyId = new PkiId("spki:" + sha256Hex(spki.bytes()));

        Credential credential = new Credential(credId, command.formatId(), new IssuerRef(caId), subjectRef, validity,
                serial.toString(), publicKeyId, command.profileId(), CredentialStatus.ISSUED,
                new EncodedObject(Encoding.DER, certDer), command.attributes());

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
     * The imported root may optionally carry a {@link KeyRef}. When absent, the CA
     * is still represented in the store, but later signing operations may be
     * unavailable depending on higher-level policy and runtime wiring.
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

        X509CertificateHolder holder;
        try {
            holder = new X509CertificateHolder(command.existingCaCredential().bytes());
        } catch (Exception ex) {
            throw new PkiException("Invalid X.509 credential payload", ex);
        }

        Instant notBefore = holder.getNotBefore().toInstant();

        Instant notAfter = holder.getNotAfter().toInstant();
        Validity validity = new Validity(notBefore, notAfter);

        byte[] certDer = command.existingCaCredential().bytes();
        PkiId credId = new PkiId("x509:" + sha256Hex(certDer));
        PkiId caId = new PkiId("ca:" + sha256Hex(certDer).substring(0, 16));

        byte[] spkiDer;
        try {
            spkiDer = holder.getSubjectPublicKeyInfo().getEncoded();
        } catch (java.io.IOException ex) {
            throw new PkiException("Failed to encode subject public key info", ex);
        }

        PkiId publicKeyId = new PkiId("spki:" + sha256Hex(spkiDer));

        BigInteger serial = holder.getSerialNumber();
        Credential credential = new Credential(credId, command.formatId(), new IssuerRef(caId), command.subjectRef(),
                validity, serial.toString(), publicKeyId, command.profileId(), CredentialStatus.ISSUED,
                new EncodedObject(Encoding.DER, certDer), command.attributes());
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

        PkiId caId = new PkiId("ca:" + sha256Hex((issuer.caId().value() + "\n" + command.subjectRef().value())
                .getBytes(java.nio.charset.StandardCharsets.UTF_8)).substring(0, 16));

        IntermediateCertIssueCommand issue = new IntermediateCertIssueCommand(command.formatId(), command.issuerCaId(),
                caId, command.profileId(), Optional.empty(), command.attributes());

        Credential cred = framework.issuerBackend().issueIntermediateCertificate(issue);
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

        Credential cred = framework.issuerBackend().issueIntermediateCertificate(command);
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

    private static String sha256Hex(byte[] in) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(in));
        } catch (Exception ex) {
            throw new IllegalStateException("SHA-256 not available", ex);
        }
    }

    /**
     * {@link ContentSigner} implementation that delegates the actual signature
     * operation to {@link PkiSigningBus}.
     *
     * <p>
     * This signer acts as an adapter between the Bouncy Castle certificate
     * construction pipeline and the ZeroEcho asynchronous signing infrastructure.
     * The to-be-signed bytes written through {@link #getOutputStream()} are
     * buffered in memory and, when {@link #getSignature()} is invoked, are
     * submitted to the signing bus as a delegated signing request bound to the
     * configured {@link KeyRef}.
     * </p>
     *
     * <p>
     * Although the underlying signing subsystem is asynchronous, this adapter
     * exposes the synchronous {@link ContentSigner} contract required by Bouncy
     * Castle. It therefore performs bounded polling until the signing workflow
     * completes successfully, fails, or reaches the configured timeout.
     * </p>
     *
     * <h2>Security considerations</h2>
     * <ul>
     * <li>The private key is never accessed directly by this class.</li>
     * <li>The signer only transports the to-be-signed payload and consumes the
     * resulting signature bytes.</li>
     * <li>The buffered payload may contain certificate TBSCertificate data and must
     * therefore be treated as sensitive operational material even though it is not
     * secret key material.</li>
     * <li>Callers should ensure that the configured {@code algId} is compatible
     * with the referenced key material and with the expectations of the downstream
     * signing implementation.</li>
     * </ul>
     *
     * <h2>Thread-safety</h2>
     * <p>
     * Instances of this class are not thread-safe. A signer instance is intended
     * for a single certificate-building flow and maintains mutable in-memory state
     * through its internal output buffer.
     * </p>
     */
    private static final class BusBackedContentSigner implements ContentSigner {

        private final PkiSigningBus bus;
        private final KeyRef keyRef;
        private final String algId;
        private final Duration ttl;
        private final java.io.ByteArrayOutputStream baos;

        /**
         * Creates a signer that routes signing requests through the supplied signing
         * bus.
         *
         * <p>
         * The signer buffers all bytes written to its output stream and later submits
         * them as a single signing request. The {@code ttl} defines the maximum time
         * window allowed for the delegated signing workflow to complete.
         * </p>
         *
         * @param bus    signing bus used to submit and track the delegated signing
         *               workflow; must not be {@code null}
         * @param keyRef opaque reference identifying the signing key to be used by the
         *               downstream signing implementation; must not be {@code null}
         * @param algId  signature algorithm identifier understood both by Bouncy Castle
         *               and the downstream signing path; must not be {@code null} or
         *               blank
         * @param ttl    positive maximum duration to wait for signing completion
         */
        private BusBackedContentSigner(PkiSigningBus bus, KeyRef keyRef, String algId, Duration ttl) {
            this.bus = bus;
            this.keyRef = keyRef;
            this.algId = algId;
            this.ttl = ttl;
            this.baos = new java.io.ByteArrayOutputStream();
        }

        /**
         * Returns the algorithm identifier corresponding to the configured signature
         * algorithm name.
         *
         * <p>
         * This value is consumed by Bouncy Castle during certificate construction to
         * encode the signature algorithm metadata into the resulting certificate
         * structure.
         * </p>
         *
         * @return ASN.1 algorithm identifier for the configured signature algorithm
         * @throws RuntimeException if the configured algorithm identifier cannot be
         *                          resolved by the Bouncy Castle finder implementation
         */
        @Override
        public org.bouncycastle.asn1.x509.AlgorithmIdentifier getAlgorithmIdentifier() {
            return new DefaultSignatureAlgorithmIdentifierFinder().find(algId);
        }

        /**
         * Returns the output stream that collects the to-be-signed bytes.
         *
         * <p>
         * Data written to this stream is retained in memory until
         * {@link #getSignature()} is called. The returned stream is backed by the
         * signer instance itself and should be used only within the active signing
         * flow.
         * </p>
         *
         * @return mutable in-memory output stream receiving the to-be-signed payload
         */
        @Override
        public java.io.OutputStream getOutputStream() {
            return baos;
        }

        /**
         * Submits the buffered to-be-signed payload to the signing bus and waits for
         * the resulting signature bytes.
         *
         * <p>
         * This method bridges the synchronous {@link ContentSigner} API to the
         * asynchronous ZeroEcho signing workflow. It creates an operation identifier,
         * submits the signing request, repeatedly sweeps and polls the signing bus, and
         * returns the produced signature once the workflow reaches the successful
         * terminal state.
         * </p>
         *
         * <p>
         * On successful completion or explicit workflow failure, the associated
         * workflow state is deleted from the bus. If the timeout expires before a
         * terminal state is observed, a {@link PkiException} is raised.
         * </p>
         *
         * @return raw signature bytes produced by the delegated signing operation
         * @throws PkiException if the signing workflow fails, if no signature result is
         *                      available after a reported success state, or if signing
         *                      does not complete within the configured TTL
         */
        @Override
        public byte[] getSignature() {
            byte[] tbs = baos.toByteArray();
            PkiId clientOpId = new PkiId("sign:root:" + Math.abs(System.nanoTime()));
            zeroecho.pki.api.audit.Principal owner = new zeroecho.pki.api.audit.Principal("SYSTEM", "pki");
            PkiId opId = bus.canonicalizeOperationId(clientOpId, owner);
            EncodedObject payload = new EncodedObject(Encoding.BINARY, tbs);

            zeroecho.pki.api.audit.AccessContext ac = new zeroecho.pki.api.audit.AccessContext(owner,
                    new zeroecho.pki.api.audit.Purpose("X509_SIGN"), Optional.empty(), Optional.empty());
            PkiSigningBus.SignContinuation cont = new PkiSigningBus.SignContinuation(ac, algId, payload, keyRef,
                    Encoding.BINARY, Optional.empty());

            bus.submitSign(opId, owner, keyRef, algId, payload, ttl, Optional.of(cont.encode()));

            Instant deadline = Instant.now().plus(ttl);
            while (Instant.now().isBefore(deadline)) {
                bus.sweep(Instant.now());
                Optional<zeroecho.pki.util.async.AsyncStatus> st = bus.status(opId);
                if (st.isPresent() && st.get().state() == zeroecho.pki.util.async.AsyncState.SUCCEEDED) {
                    Optional<EncodedObject> res = bus.consumeResult(opId);
                    bus.deleteWorkflowState(opId);
                    if (res.isEmpty()) {
                        throw new PkiException("Missing signature result");
                    }
                    return res.get().bytes();
                }
                if (st.isPresent() && st.get().state() == zeroecho.pki.util.async.AsyncState.FAILED) {
                    bus.deleteWorkflowState(opId);
                    throw new PkiException("Signing failed");
                }
            }
            throw new PkiException("Signing did not complete before TTL");
        }
    }
}
