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
package zeroecho.pki.server.est;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;


import zeroecho.core.io.CancellationSignal;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificationRequestException;
import zeroecho.pkix.Pkix;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.server.CertificateIdentityEvidence;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.server.ServerRealmContext;

/**
 * EST RFC 7030 protocol service.
 *
 * <p>Implements the five core EST operations over the lifecycle-owned realm session.
 * No BouncyCastle imports are present; all CMS/cryptographic codec operations
 * are delegated to {@link EstCmsCodec} (which delegates to {@link Pkix}).</p>
 *
 * <p>Endpoint registration uses the durable realm registry; operation
 * methods are stateless with respect to the endpoint registry and safe to call concurrently.</p>
 *
 * @since 1.0
 */
public final class EstService { // NOPMD CyclomaticComplexity - Aggregate EST protocol lifecycle complexity across the five shared realm/endpoint operations; individual methods remain checked.
    private static final String SUBJECT_ALT_NAME_OID = "2.5.29.17"; // NOPMD AvoidUsingHardCodedIP - Standard X.509 subjectAltName OID, not an IP address.
    private static final int MAX_CHAIN_CERTIFICATE_BYTES = 1_048_576;
    private static final String TEXT_ENDPOINT = "endpoint";


    /** SHA-256withRSA (PKCS#1 v1.5) OID. */
    private static final String OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    /** SHA-256withECDSA OID. */
    private static final String OID_SHA256_WITH_ECDSA = "1.2.840.10045.4.3.2";

    /** EC P-256 curve name. */
    private static final String EC_P256 = "secp256r1";
    /** Default RSA key size in bits when not otherwise constrained by policy. */
    private static final int RSA_DEFAULT_BITS = 2048;

    private final ServerRealmContext realm;
    private final zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry endpoints;

    /**
     * Creates an EST service over the given realm.
     *
     * @param realm lifecycle-owned realm context
     */
    public EstService(ServerRealmContext realm) {
        this.realm = Objects.requireNonNull(realm, "realm");
        this.endpoints = Objects.requireNonNull(realm.enrollmentEndpoints(), "enrollmentEndpoints");
    }

    // -------------------------------------------------------------------------
    // Endpoint registry
    // -------------------------------------------------------------------------

    /**
     * Registers an EST endpoint, replacing any existing endpoint with the same label.
     *
     * @param endpoint the endpoint to register
     */
    public void register(EstEndpoint endpoint) {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        endpoints.register(endpoint);
    }

    /**
     * Removes the endpoint with the given label.
     *
     * @param label URL-safe endpoint label
     * @return the removed endpoint, or empty if absent
     */
    public Optional<EstEndpoint> deregister(String label) {
        return endpoints.deregister(zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry.Protocol.EST, label)
                .map(value -> (EstEndpoint) value);
    }

    /**
     * Returns the endpoint for the given label.
     *
     * @param label URL-safe endpoint label
     * @return the endpoint, or empty when not registered
     */
    public Optional<EstEndpoint> find(String label) {
        return endpoints.find(zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry.Protocol.EST, label)
                .map(value -> (EstEndpoint) value);
    }

    /**
     * Collects active endpoints in deterministic store-key order. Concurrent
     * changes across persistence pages need not form one atomic snapshot.
     *
     * @return current endpoint list
     */
    public List<EstEndpoint> list() {
        return endpoints.list(zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry.Protocol.EST)
                .stream().map(value -> (EstEndpoint) value).toList();
    }

    // -------------------------------------------------------------------------
    // EST operations
    // -------------------------------------------------------------------------

    /**
     * Returns the CA certificate chain for the endpoint as MIME-base64-encoded
     * CMS certs-only (RFC 7030 section 4.1).
     *
     * @param endpoint the EST endpoint
     * @return MIME-base64-encoded CMS certs-only DER
     * @throws EstProtocolException if the CA or chain is unavailable
     */
    public byte[] cacerts(EstEndpoint endpoint) throws EstProtocolException {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        return EstCmsCodec.encodeCertsOnly(caChain(new PkiId(endpoint.authorityId())));
    }

    /**
     * Performs EST {@code simpleenroll} (RFC 7030 section 4.2): verifies the client CSR,
     * durably admits the request and returns its current approval or issuance outcome.
     * Completed results contain MIME-base64 CMS certificates and the frozen issuer chain.
     *
     * @param endpoint   the EST endpoint
     * @param csrBody    PKCS#10 DER, PEM, or RFC 7030 base64; self-signature must be valid
     * @param clientCert authenticated mTLS client certificate
     * @return completed CMS response, pending approval/signing response, or terminal rejection
     * @throws EstProtocolException if input validation or durable admission is unavailable
     */
    public EnrollmentResult simpleenroll(EstEndpoint endpoint, byte[] csrBody, X509Certificate clientCert)
            throws EstProtocolException {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        Objects.requireNonNull(csrBody, "csrBody");
        Objects.requireNonNull(clientCert, "clientCert");

        return simpleenroll(endpoint, csrBody, clientCert, CancellationSignal.NONE);
    }

    /**
     * Admits or continues enrollment with cancellation before the durable signing claim.
     * @param endpoint exact endpoint
     * @param csrBody bounded original PKCS#10 DER, PEM, or base64
     * @param clientCert verified TLS end-client certificate
     * @param cancellation transport cancellation signal
     * @return durable response outcome
     * @throws EstProtocolException if validation or admission fails
     */
    public EnrollmentResult simpleenroll(EstEndpoint endpoint, byte[] csrBody, X509Certificate clientCert,
            CancellationSignal cancellation) throws EstProtocolException {
        return enroll(endpoint, csrBody, clientCert, EnrollmentTransaction.Operation.ISSUE, cancellation);
    }

    /**
     * Performs EST {@code simplereenroll} (RFC 7030 section 4.2.2): renews the client's
     * certificate after proving the authoritative predecessor identity and satisfying
     * the frozen approval and proof policy. Repeated identical requests retain one operation.
     *
     * @param endpoint   the EST endpoint
     * @param csrBody    renewal PKCS#10 DER, PEM, or base64; self-signature must be valid
     * @param clientCert authenticated mTLS client certificate (the predecessor)
     * @return completed CMS response, pending approval/signing response, or terminal rejection
     * @throws EstProtocolException if identity validation or durable admission is unavailable
     */
    public EnrollmentResult simplereenroll(EstEndpoint endpoint, byte[] csrBody, X509Certificate clientCert)
            throws EstProtocolException {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        Objects.requireNonNull(csrBody, "csrBody");
        Objects.requireNonNull(clientCert, "clientCert");

        return simplereenroll(endpoint, csrBody, clientCert, CancellationSignal.NONE);
    }

    /**
     * Admits or continues exact-identity renewal with pre-claim cancellation.
     * @param endpoint exact endpoint
     * @param csrBody bounded original PKCS#10 DER, PEM, or base64
     * @param clientCert verified TLS predecessor certificate
     * @param cancellation transport cancellation signal
     * @return durable response outcome
     * @throws EstProtocolException if validation or admission fails
     */
    public EnrollmentResult simplereenroll(EstEndpoint endpoint, byte[] csrBody, X509Certificate clientCert,
            CancellationSignal cancellation) throws EstProtocolException {
        return enroll(endpoint, csrBody, clientCert, EnrollmentTransaction.Operation.RENEW, cancellation);
    }

    /**
     * Immutable EST enrollment response. Pending work carries an explicit retry
     * interval; terminal responses never masquerade as pending approval.
     * @param status HTTP response status
     * @param body completed MIME-base64 CMS or empty for non-success responses
     * @param retryAfterSeconds positive interval only for HTTP 202
     */
    public record EnrollmentResult(int status, byte[] body, Optional<Long> retryAfterSeconds) {
        /** Validates response state and defensively copies the response body. */
        public EnrollmentResult {
            body = Objects.requireNonNull(body, "body").clone();
            Objects.requireNonNull(retryAfterSeconds, "retryAfterSeconds");
            if (status != 200 && status != 202 && status != 403 && status != 410 && status != 500
                    || status == 202 != retryAfterSeconds.isPresent() || retryAfterSeconds.filter(value -> value < 1).isPresent()
                    || status != 200 && body.length != 0) {
                throw new IllegalArgumentException("Invalid EST enrollment result");
            }
        }
        /**
         * Returns a defensive copy.
         * @return independently owned response bytes
         */
        @Override public byte[] body() { return body.clone(); }
        /** @return response status without body content */
        @Override public String toString() { return "EnrollmentResult[status=" + status + "]"; }
    }

    private EnrollmentResult enroll(EstEndpoint endpoint, byte[] body, X509Certificate certificate, EnrollmentTransaction.Operation operation,
            CancellationSignal cancellation)
            throws EstProtocolException {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        Objects.requireNonNull(certificate, "clientCert");
        Objects.requireNonNull(cancellation, "cancellation");
        try {
            byte[] original = requireValidCsr(body);
            CertificateIdentityEvidence evidence = CertificateIdentityEvidence.fromCertificate(realm.configuration().realmId(), certificate);
            EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.EST_CLIENT,
                    evidence.certificateSha256(), IssuanceExecutionEvidence.Authentication.EST_MTLS, Optional.of(evidence),
                    Optional.of(evidence.canonicalKeySha256()), evidence.legacySpkiSha256(),
                    new EnrollmentIdentityAliases.Snapshot(realm.configuration().realmId(), java.util.Set.of()));
            EnrollmentCoordinator coordinator = realm.enrollmentCoordinator().orElseThrow(() -> new IllegalStateException("Enrollment unavailable")); // NOPMD CloseResource - Borrowed realm coordinator; the realm owns its shutdown.
            EnrollmentTransaction value = coordinator.admit(new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.EST, endpoint.label(), requester,
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original)), operation,
                    new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, original), Optional.empty(),
                    operation == EnrollmentTransaction.Operation.RENEW ? Optional.of(credentialIdFor(certificate)) : Optional.empty()));
            value = coordinator.dispatch(value.id(), cancellation);
            return switch (value.state()) {
                case ISSUED -> new EnrollmentResult(200, EstCmsCodec.encodeCertsOnly(retainedChain(value)), Optional.empty());
                case REJECTED -> new EnrollmentResult(403, new byte[0], Optional.empty());
                case EXPIRED -> new EnrollmentResult(410, new byte[0], Optional.empty());
                case FAILED -> new EnrollmentResult(500, new byte[0], Optional.empty());
                default -> new EnrollmentResult(202, new byte[0], Optional.of(Math.max(1,
                        realm.enrollmentRuntime().orElseThrow().configuration().budgets().retryAfter().toSeconds())));
            };
        } catch (IllegalArgumentException invalid) {
            throw new EstProtocolException(400, "EST enrollment input is invalid"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        } catch (java.security.GeneralSecurityException | IllegalStateException unavailable) {
            throw new EstProtocolException(503, "EST enrollment is unavailable"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    private List<X509Certificate> retainedChain(EnrollmentTransaction value) throws EstProtocolException {
        PkiRepository repository = realm.session().repository();
        IssuerChainPath path = repository.chainPath(value.intent().pathId()).orElseThrow(() -> new EstProtocolException(503, "EST frozen path is unavailable"));
        List<PkiId> ids = new ArrayList<>(); ids.add(value.credentialId().orElseThrow()); ids.addAll(path.orderedCredentialIds());
        List<X509Certificate> certificates = new ArrayList<>();
        for (PkiId id : ids) {
            try (PkiRepositoryContent content = repository.openCredential(id); InputStream input = content.openStream()) {
                byte[] der = input.readNBytes(1_048_577);
                if (der.length > MAX_CHAIN_CERTIFICATE_BYTES) {
                    throw new EstProtocolException(503, "EST credential exceeds the size limit");
                }
                certificates.add(parseCertificate(der));
            } catch (IOException failure) { throw new EstProtocolException(503, "EST credential is unavailable"); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
        return List.copyOf(certificates);
    }

    /**
     * Returns CSR attribute suggestions as MIME-base64-encoded RFC 7030 {@code CsrAttrs} DER
     * (RFC 7030 section 4.5).
     *
     * @param endpoint the EST endpoint
     * @return MIME-base64-encoded CsrAttrs DER (empty sequence when no suggestions)
     */
    public byte[] csrattrs(EstEndpoint endpoint) {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        return EstCmsCodec.encodeCsrAttrs(List.of());
    }

    /**
     * Performs server-key generation through durable encrypted-artifact admission.
     * This overload has no caller cancellation signal.
     * @param endpoint registered endpoint
     * @param csrBody exact DER, PEM or MIME-base64 PKCS#10 template
     * @param clientCert authenticated TLS recipient
     * @return pending, terminal or lazily leased encrypted delivery
     * @throws EstProtocolException if validation or custody is unavailable
     */
    public EstServerKeygenResponse serverkeygen(EstEndpoint endpoint, byte[] csrBody,
            X509Certificate clientCert) throws EstProtocolException {
        return serverkeygen(endpoint, csrBody, clientCert, CancellationSignal.NONE);
    }

    /**
     * Freezes the authenticated original template and reserves capacity before
     * generating a key. Ciphertext is generator-signed, encrypted and durably
     * attached before approval or issuance. Exact retries resume the retained
     * transaction and never regenerate a key. Template proof is ignored as required
     * by RFC 7030; the generated CSR undergoes normal frozen-profile proof checks.
     * @param endpoint registered endpoint
     * @param csrBody original template in DER, PEM or MIME-base64 form
     * @param clientCert actual authenticated TLS recipient
     * @param cancellation checked before generation, attachment and dispatch
     * @return typed protocol status with resource-free deferred delivery
     * @throws EstProtocolException if input, negotiation, policy or custody fails
     */
    public EstServerKeygenResponse serverkeygen(EstEndpoint endpoint, byte[] csrBody,
            X509Certificate clientCert, CancellationSignal cancellation) throws EstProtocolException {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT); Objects.requireNonNull(clientCert, "clientCert");
        Objects.requireNonNull(cancellation, "cancellation");
        try {
            cancellation.throwIfCancelled();
            byte[] original = templateDer(csrBody);
            zeroecho.pkix.EstKeygen.requireRecipient(original, clientCert);
            CertificateIdentityEvidence evidence = CertificateIdentityEvidence.fromCertificate(realm.configuration().realmId(), clientCert);
            EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.EST_CLIENT,
                    evidence.certificateSha256(), IssuanceExecutionEvidence.Authentication.EST_MTLS, Optional.of(evidence),
                    Optional.of(evidence.canonicalKeySha256()), evidence.legacySpkiSha256(),
                    new EnrollmentIdentityAliases.Snapshot(realm.configuration().realmId(), java.util.Set.of()));
            EnrollmentCoordinator.Admission admission = new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.EST, endpoint.label(), requester,
                    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original)), EnrollmentTransaction.Operation.SERVER_KEYGEN,
                    new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, original), Optional.empty(), Optional.empty());
            EnrollmentCoordinator coordinator = realm.enrollmentCoordinator().orElseThrow(() -> new IllegalStateException("Enrollment unavailable"));
            Optional<zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact> retained = coordinator.findKeygen(admission);
            if (retained.isEmpty()) {
                cancellation.throwIfCancelled();
                try (EnrollmentCoordinator.KeygenGeneration generation = coordinator.beginKeygen(admission, clientCert)) {
                    zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact descriptor = generation.descriptor();
                    try (zeroecho.pki.server.enrollment.EnrollmentRuntime.CredentialLease signer = realm.enrollmentRuntime().orElseThrow()
                            .acquire(descriptor.template().source().credentialId().orElseThrow())) {
                        cancellation.throwIfCancelled();
                        KeyPair key = generateKeyPair(descriptor.algorithm(), descriptor.maximumKeySizeBits());
                        cancellation.throwIfCancelled();
                        byte[] generated = generatedRequest(original, key, descriptor.algorithm());
                        byte[] privateKey = key.getPrivate().getEncoded();
                        if (privateKey == null) {
                            throw new IllegalStateException("Generated key is not encodable");
                        }
                        try {
                            cancellation.throwIfCancelled();
                            byte[] encrypted = zeroecho.pkix.EstKeygen.signedEncryptedPackage(original, privateKey, clientCert, signer.responseChain(),
                                    Pkix.signer(signer.privateKey(), signingAlgorithmFor(signer.privateKey().getAlgorithm())));
                            cancellation.throwIfCancelled();
                            generation.attach(new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, generated), encrypted);
                        } finally { Arrays.fill(privateKey, (byte) 0); }
                    }
                }
            }
            zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact descriptor = coordinator.findKeygen(admission).orElseThrow();
            if (descriptor.state() == zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.EXPIRED) {
                return EstServerKeygenResponse.terminal(410);
            }
            if (descriptor.state() == zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.FAILED) {
                return EstServerKeygenResponse.terminal(500);
            }
            if (descriptor.state() == zeroecho.pki.server.enrollment.EnrollmentKeygenArtifact.State.GENERATING) {
                return keygenPending();
            }
            EnrollmentTransaction enrollment = coordinator.dispatch(descriptor.enrollmentId(), cancellation);
            return switch (enrollment.state()) {
                case ISSUED -> EstServerKeygenResponse.issued(coordinator, admission, descriptor.id(), EstCmsCodec.encodeCertsOnly(retainedChain(enrollment)));
                case REJECTED -> EstServerKeygenResponse.terminal(403);
                case EXPIRED -> EstServerKeygenResponse.terminal(410);
                case FAILED -> EstServerKeygenResponse.terminal(500);
                default -> keygenPending();
            };
        } catch (java.io.InterruptedIOException cancelled) {
            throw new EstProtocolException(503, "EST key generation cancelled"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        } catch (IllegalArgumentException | zeroecho.pki.api.PkiException invalid) {
            throw new EstProtocolException(400, "EST key-generation input is invalid"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        } catch (java.security.GeneralSecurityException | IllegalStateException unavailable) { // NOPMD ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
            throw new EstProtocolException(503, "EST key generation is unavailable"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }

    private EstServerKeygenResponse keygenPending() {
        return EstServerKeygenResponse.pending(Math.max(1, realm.enrollmentRuntime().orElseThrow().configuration().budgets().retryAfter().toSeconds()));
    }

    private byte[] templateDer(byte[] body) {
        if (body == null || body.length == 0 || body.length > X509EnrollmentPayload.MAXIMUM_DER_BYTES * 2) {
            throw new IllegalArgumentException("Invalid EST template size");
        }
        byte[] encoded = body;
        if (body[0] != 0x30 && body[0] != '-') {
            StringBuilder compact = new StringBuilder(body.length);
            for (byte value : body) {
                if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
                    compact.append((char) (value & 255));
                }
            }
            encoded = Base64.getDecoder().decode(compact.toString());
        }
        if (encoded.length == 0) {
            throw new IllegalArgumentException("Empty EST template");
        }
        zeroecho.pki.api.CertificationRequestService requests = realm.session().requests().orElseThrow();
        zeroecho.pki.api.request.ParsedCertificationRequest parsed = requests.parse(new zeroecho.pki.api.request.CertificationRequest(
                new zeroecho.pki.api.FormatId("x509"), new zeroecho.pki.api.EncodedObject(encoded[0] == '-'
                        ? zeroecho.pki.api.Encoding.PEM : zeroecho.pki.api.Encoding.DER, encoded)));
        return requests.encodedX509Request(parsed).der();
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private byte[] requireValidCsr(byte[] csrBody) throws EstProtocolException {
        try {
            if (csrBody == null || csrBody.length == 0 || csrBody.length > X509EnrollmentPayload.MAXIMUM_DER_BYTES * 2) {
                throw new IllegalArgumentException("EST request size is invalid");
            }
            byte[] encoded = csrBody;
            if (csrBody[0] != 0x30 && csrBody[0] != '-') {
                StringBuilder compact = new StringBuilder(csrBody.length);
                for (byte value : csrBody) {
                    if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
                        compact.append((char) (value & 255));
                    }
                }
                encoded = Base64.getDecoder().decode(compact.toString());
            }
            return Pkix.parseCsr(encoded).encoded();
        } catch (CertificationRequestException | IllegalArgumentException failure) { // NOPMD ExceptionAsFlowControl - Invalid input is rejected here and normalized at the protocol boundary; exceptions do not represent successful control flow.
            throw new EstProtocolException(400, "EST CSR is invalid"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        }
    }


    private List<X509Certificate> caChain(PkiId authorityId) throws EstProtocolException {
        PkiRepository repository = realm.session().repository();
        CaRecord authority = repository.authority(authorityId)
                .orElseThrow(() -> new EstProtocolException(503, "EST CA authority is unavailable"));
        IssuerChainPath path = repository.chainPath(authority.issuanceChainPathId())
                .orElseThrow(() -> new EstProtocolException(503, "EST CA chain path is unavailable"));
        List<X509Certificate> chain = new ArrayList<>();
        for (PkiId credId : path.orderedCredentialIds()) {
            try (PkiRepositoryContent content = repository.openCredential(credId);
                 InputStream in = content.openStream()) {
                chain.add(parseCertificate(in.readAllBytes()));
            } catch (IOException failure) {
                throw new EstProtocolException(503, "EST CA certificate is unreadable", failure);
            }
        }
        return List.copyOf(chain);
    }

    private static byte[] generatedRequest(byte[] original, KeyPair key, String algorithm) throws EstProtocolException {
        CertificationRequest template = Pkix.parseCertificationRequest(original);
        zeroecho.pkix.csr.CertificationRequestBuilder builder = Pkix.certificationRequestBuilder()
                .subject(template.subject()).publicKey(key.getPublic());
        for (zeroecho.pkix.CertificateExtension extension : template.requestedExtensions()) {
            if (SUBJECT_ALT_NAME_OID.equals(extension.oid())) {
                builder.requestExtension(extension);
            }
        }
        return builder.build(Pkix.signer(key.getPrivate(), signingAlgorithmFor(algorithm))).encoded();
    }

    private static X509Certificate parseCertificate(byte[] der) throws EstProtocolException {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception failure) {
            throw new EstProtocolException(500, "EST certificate parsing failed", failure);
        }
    }


    private static PkiId credentialIdFor(X509Certificate cert) throws EstProtocolException {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
            return new PkiId("x509:" + HexFormat.of().formatHex(digest));
        } catch (Exception failure) {
            throw new EstProtocolException(500, "EST credential ID derivation failed", failure);
        }
    }

    private static KeyPair generateKeyPair(String jcaAlg, int maximumKeySizeBits)
            throws EstProtocolException {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(jcaAlg);
            switch (jcaAlg.toUpperCase(java.util.Locale.ROOT)) {
                case "RSA" -> kpg.initialize(Math.min(maximumKeySizeBits, RSA_DEFAULT_BITS));
                case "EC" -> kpg.initialize(new ECGenParameterSpec(EC_P256));
                default -> throw new EstProtocolException(422,
                        "EST server keygen algorithm not supported: " + jcaAlg);
            }
            return kpg.generateKeyPair();
        } catch (EstProtocolException ex) {
            throw ex;
        } catch (Exception failure) {
            throw new EstProtocolException(500, "EST key generation failed", failure);
        }
    }

    private static AlgorithmIdentifier signingAlgorithmFor(String jcaAlg) throws EstProtocolException {
        return switch (jcaAlg.toUpperCase(java.util.Locale.ROOT)) {
            case "RSA" -> AlgorithmIdentifier.derNull(OID_SHA256_WITH_RSA);
            case "EC" -> AlgorithmIdentifier.absent(OID_SHA256_WITH_ECDSA);
            default -> throw new EstProtocolException(422,
                    "EST signing algorithm not supported for serverkeygen: " + jcaAlg);
        };
    }
}
