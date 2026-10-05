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
package zeroecho.pki.server.scep;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.x500.X500Principal;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.CertificationRequestException;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.scep.ScepCodec;
import zeroecho.pkix.scep.ScepCodecException;
import zeroecho.pkix.scep.ScepPkiMessage;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.server.RepositoryAliasService;
import zeroecho.pki.server.ServerRealmContext;

/**
 * SCEP RFC 8894 protocol service.
 *
 * <p>Manages the endpoint registry and coordinates SCEP protocol operations.
 * The RA signing key pair is generated once at startup (ephemeral RSA-2048);
 * no BouncyCastle imports appear in this class — all codec work is delegated
 * to {@link ScepCodec} in the lib module.</p>
 *
 * @since 1.0
 */
@SuppressWarnings("PMD.SignatureDeclareThrowsException")
public final class ScepService { // NOPMD CyclomaticComplexity - Aggregate lifecycle/coordinator complexity; individual methods remain checked.

    /** SHA-256withRSA OID. */
    private static final String OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";

    /** Maximum wait for signing completion. */
    private static final long SIGNING_POLL_TIMEOUT_MS = 60_000L;
    /** Interval between signing completion polls. */
    private static final long SIGNING_POLL_INTERVAL_MS = 100L;

    private final ServerRealmContext realm;
    private final ConcurrentMap<String, ScepEndpoint> endpoints = new ConcurrentHashMap<>();
    /** Maps transactionId → operationId for pending GetCertInitial tracking. */
    private final ConcurrentMap<String, PkiId> pendingOperations = new ConcurrentHashMap<>();

    private final PrivateKey raPrivateKey;
    private final X509Certificate raCert;

    /**
     * Creates a SCEP service over the given realm.
     * An ephemeral RSA-2048 RA signing key pair is generated at construction time.
     *
     * @param realm lifecycle-owned realm context
     */
    public ScepService(ServerRealmContext realm) {
        this.realm = Objects.requireNonNull(realm, "realm");
        KeyPair raKeyPair = generateRaKeyPair();
        this.raPrivateKey = raKeyPair.getPrivate();
        this.raCert = buildRaCert(raKeyPair);
    }

    // -------------------------------------------------------------------------
    // Endpoint registry
    // -------------------------------------------------------------------------

    /**
     * Registers a SCEP endpoint, replacing an existing entry with the same label.
     * @param endpoint non-null endpoint configuration
     */
    public void register(ScepEndpoint endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        endpoints.put(endpoint.label(), endpoint);
    }

    /**
     * Removes the endpoint with the given label.
     * @param label non-null registry label
     * @return the removed endpoint, or empty if no entry existed
     */
    public Optional<ScepEndpoint> deregister(String label) {
        return Optional.ofNullable(endpoints.remove(Objects.requireNonNull(label, "label")));
    }

    /**
     * Looks up the endpoint for the given label.
     * @param label non-null registry label
     * @return the observed endpoint, or empty if absent
     */
    public Optional<ScepEndpoint> find(String label) {
        return Optional.ofNullable(endpoints.get(Objects.requireNonNull(label, "label")));
    }

    /**
     * Copies endpoints observed during a weakly consistent registry traversal.
     * @return an immutable list in unspecified order; concurrent changes are not
     *         represented as an atomic point-in-time snapshot
     */
    public List<ScepEndpoint> list() {
        return List.copyOf(endpoints.values());
    }

    // -------------------------------------------------------------------------
    // SCEP protocol operations
    // -------------------------------------------------------------------------

    /**
     * Returns the SCEP RA certificate DER for {@code GetCACert} when only a single
     * CA cert is needed, or a degenerate CMS certs-only chain for multi-CA.
     *
     * <p>RFC 8894 §4.2: a single CA cert is returned as plain DER (content-type
     * {@code application/x-x509-ca-cert}); a chain returns CMS certs-only
     * ({@code application/x-x509-ca-ra-cert}).</p>
     *
     * @param endpoint the SCEP endpoint
     * @return DER-encoded issuing CA certificate
     * @throws ScepProtocolException if the CA is unavailable
     */
    public byte[] getCaCert(ScepEndpoint endpoint) throws ScepProtocolException {
        Objects.requireNonNull(endpoint, "endpoint");
        List<X509Certificate> chain = caChain(new PkiId(endpoint.authorityId()));
        if (chain.isEmpty()) {
            throw new ScepProtocolException("SCEP CA chain is empty for authority: " + endpoint.authorityId());
        }
        try {
            return chain.get(0).getEncoded();
        } catch (Exception e) {
            throw new ScepProtocolException("Failed to encode SCEP CA certificate", e);
        }
    }

    /**
     * Returns a degenerate CMS certs-only SignedData for {@code GetCACertChain}.
     *
     * @param endpoint the SCEP endpoint
     * @return DER-encoded CMS certs-only content
     * @throws ScepProtocolException if the chain is unavailable or encoding fails
     */
    public byte[] getCaCertChain(ScepEndpoint endpoint) throws ScepProtocolException {
        Objects.requireNonNull(endpoint, "endpoint");
        List<X509Certificate> chain = caChain(new PkiId(endpoint.authorityId()));
        try {
            List<byte[]> certsDer = new ArrayList<>();
            certsDer.add(raCert.getEncoded());
            for (X509Certificate c : chain) {
                certsDer.add(c.getEncoded());
            }
            return ScepCodec.buildDegenerateCertsCms(certsDer);
        } catch (Exception e) {
            throw new ScepProtocolException("Failed to build SCEP CA cert chain", e);
        }
    }

    /**
     * Processes a SCEP {@code PKIOperation} request (PKCSReq, GetCertInitial,
     * GetCert, GetCRL) and returns a CertRep CMS SignedData response.
     *
     * @param endpoint    the SCEP endpoint
     * @param messageData raw CMS SignedData bytes from the HTTP request body
     * @return DER-encoded CertRep CMS response
     * @throws ScepProtocolException if message decoding or issuance fails
     */
    public byte[] processPkiOperation(ScepEndpoint endpoint, byte[] messageData)
            throws ScepProtocolException {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(messageData, "messageData");

        ScepPkiMessage request;
        try {
            request = ScepCodec.parsePkiOperationDer(messageData, raPrivateKey);
        } catch (ScepCodecException e) {
            throw new ScepProtocolException("Failed to parse SCEP PKIOperation", e);
        }

        return switch (request.messageType()) {
            case ScepCodec.MSG_PKCS_REQ -> handlePkcsReq(endpoint, request);
            case ScepCodec.MSG_GET_CERT_INITIAL -> handleGetCertInitial(request);
            case ScepCodec.MSG_GET_CERT -> buildFailure(request, ScepCodec.FAIL_BAD_CERT_ID,
                    "GetCert not supported via SCEP; use EST");
            case ScepCodec.MSG_GET_CRL -> handleGetCrl(endpoint, request);
            default -> buildFailure(request, ScepCodec.FAIL_BAD_REQUEST,
                    "Unknown SCEP message type: " + request.messageType());
        };
    }

    // -------------------------------------------------------------------------
    // Private: PKCSReq handler
    // -------------------------------------------------------------------------

    private byte[] handlePkcsReq(ScepEndpoint endpoint, ScepPkiMessage request)
            throws ScepProtocolException {
        byte[] csrDer = request.innerContent();
        if (csrDer == null || csrDer.length == 0) {
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, "PKCSReq inner content is empty");
        }

        // Validate CSR self-signature via Pkix facade
        try {
            Pkix.parseCsr(csrDer);
        } catch (CertificationRequestException e) {
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, "PKCSReq CSR is invalid: " + e.getMessage());
        }

        // Verify challenge password if configured
        String challenge;
        try {
            challenge = ScepCodec.extractChallengePassword(csrDer);
        } catch (ScepCodecException e) {
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, "Failed to extract challenge password");
        }
        if (!verifyChallengePassword(challenge, endpoint.challengePasswordHash())) {
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, "Challenge password mismatch");
        }

        // Submit issuance request
        AccessContext access = new AccessContext(
                new Principal("SCEP", request.transactionId()),
                new Purpose("SCEP_PKCSREQ"),
                Optional.of(new PkiId(endpoint.authorityId())),
                Optional.empty());
        EndEntityIssuanceRequest issuanceRequest = new EndEntityIssuanceRequest(
                new PkiId(endpoint.authorityId()), csrDer, endpoint.profileId(), Optional.empty());

        SemanticSigningService signing = requireSigning();
        PreparedSemanticSigningRequest prepared;
        try {
            prepared = signing.prepareEndEntity(access, issuanceRequest, Optional.empty(), CancellationSignal.NONE);
        } catch (Exception e) {
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, "SCEP issuance preparation failed: " + e.getMessage());
        }

        SigningAcceptanceResult accepted;
        try {
            accepted = signing.accept(prepared);
        } catch (Exception e) {
            throw new ScepProtocolException("SCEP signing acceptance failed", e);
        }

        if (accepted.disposition() == SigningAcceptanceDisposition.CAPACITY_REJECTED) {
            // Return PENDING — client should poll with GetCertInitial
            pendingOperations.put(request.transactionId(), accepted.receipt().operationId());
            return buildPending(request);
        }
        if (accepted.disposition() == SigningAcceptanceDisposition.CONFLICT) {
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, "SCEP signing conflict");
        }

        // Poll for completion
        SemanticSigningOperation completed;
        try {
            completed = pollForCompletion(signing, accepted.receipt().operationId());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Restore cancellation before the protocol response.
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, "SCEP signing interrupted");
        } catch (Exception e) {
            // Operation still in progress — return PENDING and track it
            pendingOperations.put(request.transactionId(), accepted.receipt().operationId());
            return buildPending(request);
        }

        byte[] issuedCertDer;
        try {
            issuedCertDer = completed.result()
                    .orElseThrow(() -> new ScepProtocolException("SCEP signing result is absent"))
                    .bytes();
        } catch (ScepProtocolException e) {
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, e.getMessage());
        }

        // Build success response
        X509Certificate requesterCert = request.requesterCert();
        if (requesterCert == null) {
            return buildFailure(request, ScepCodec.FAIL_BAD_REQUEST,
                    "PKCSReq requester certificate not found in CMS");
        }
        try {
            return ScepCodec.buildCertRepSuccess(request.transactionId(), request.senderNonce(),
                    issuedCertDer, requesterCert, raCert, raPrivateKey);
        } catch (ScepCodecException e) {
            throw new ScepProtocolException("Failed to encode SCEP CertRep SUCCESS", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private: GetCertInitial handler (poll for pending operations)
    // -------------------------------------------------------------------------

    private byte[] handleGetCertInitial(ScepPkiMessage request) throws ScepProtocolException {
        PkiId operationId = pendingOperations.get(request.transactionId());
        if (operationId == null) {
            // No pending operation known; return PENDING for client to retry later
            return buildPending(request);
        }

        SemanticSigningService signing = requireSigning();
        Optional<SemanticSigningOperation> snapshot = signing.find(operationId);
        if (snapshot.isEmpty()) {
            return buildPending(request);
        }
        SemanticSigningOperation op = snapshot.get();
        return switch (op.state()) {
            case COMPLETED -> {
                pendingOperations.remove(request.transactionId());
                byte[] issuedCertDer;
                try {
                    issuedCertDer = op.result()
                            .orElseThrow(() -> new ScepProtocolException("SCEP result absent"))
                            .bytes();
                } catch (ScepProtocolException e) {
                    yield buildFailure(request, ScepCodec.FAIL_BAD_REQUEST, e.getMessage());
                }
                X509Certificate requesterCert = request.requesterCert();
                if (requesterCert == null) {
                    yield buildFailure(request, ScepCodec.FAIL_BAD_REQUEST,
                            "GetCertInitial requester cert not found");
                }
                try {
                    yield ScepCodec.buildCertRepSuccess(request.transactionId(), request.senderNonce(),
                            issuedCertDer, requesterCert, raCert, raPrivateKey);
                } catch (ScepCodecException e) {
                    throw new ScepProtocolException("Failed to encode SCEP CertRep SUCCESS", e);
                }
            }
            case FAILED, EXPIRED -> {
                pendingOperations.remove(request.transactionId());
                yield buildFailure(request, ScepCodec.FAIL_BAD_REQUEST,
                        "SCEP pending operation " + op.state().name().toLowerCase(java.util.Locale.ROOT));
            }
            default -> buildPending(request);
        };
    }

    // -------------------------------------------------------------------------
    // Private: GetCRL handler
    // -------------------------------------------------------------------------

    private byte[] handleGetCrl(ScepEndpoint endpoint, ScepPkiMessage request)
            throws ScepProtocolException {
        PkiId authorityId = new PkiId(endpoint.authorityId());
        try {
            // Look up the current CRL alias directly from the repository alias service
            RepositoryAliasService.Record alias =
                    realm.repositoryAliases().require(authorityId, RepositoryAliasService.Type.CURRENT_CRL);
            PkiRepository repository = realm.session().repository();
            byte[] crlDer;
            try (PkiRepositoryContent content = repository.openStatusObject(alias.targetObjectId());
                 InputStream in = content.openStream()) {
                crlDer = in.readAllBytes();
            }
            // Build CertRep with the CRL as inner content (RFC 8894 §4.4)
            return ScepCodec.buildCertRepSuccess(request.transactionId(), request.senderNonce(),
                    crlDer, raCert, raCert, raPrivateKey);
        } catch (ScepCodecException e) {
            throw new ScepProtocolException("Failed to encode SCEP GetCRL response", e);
        } catch (Exception e) {
            return buildFailure(request, ScepCodec.FAIL_BAD_CERT_ID,
                    "CRL unavailable: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private byte[] buildFailure(ScepPkiMessage request, String failInfo, String reason)
            throws ScepProtocolException {
        try {
            return ScepCodec.buildCertRepFailure(request.transactionId(),
                    request.senderNonce(), failInfo, raCert, raPrivateKey);
        } catch (ScepCodecException e) {
            throw new ScepProtocolException("Failed to build SCEP failure response for: " + reason, e);
        }
    }

    private byte[] buildPending(ScepPkiMessage request) throws ScepProtocolException {
        try {
            return ScepCodec.buildCertRepPending(request.transactionId(),
                    request.senderNonce(), raCert, raPrivateKey);
        } catch (ScepCodecException e) {
            throw new ScepProtocolException("Failed to build SCEP pending response", e);
        }
    }

    private static boolean verifyChallengePassword(String challenge, String storedHash) {
        if (challenge == null || challenge.isBlank()) {
            return false;
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(challenge.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String hex = HexFormat.of().formatHex(digest);
            return hex.equals(storedHash);
        } catch (Exception e) {
            return false;
        }
    }

    private SemanticSigningService requireSigning() throws ScepProtocolException {
        return realm.session().semanticSigning()
                .orElseThrow(() -> new ScepProtocolException("SCEP signing capability is unavailable"));
    }

    private SemanticSigningOperation pollForCompletion(SemanticSigningService signing,
            PkiId operationId) throws Exception {
        long deadline = System.currentTimeMillis() + SIGNING_POLL_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            Optional<SemanticSigningOperation> snapshot = signing.find(operationId);
            if (snapshot.isPresent()) {
                SemanticSigningOperation op = snapshot.get();
                switch (op.state()) {
                    case COMPLETED -> { return op; }
                    case FAILED, EXPIRED -> throw new ScepProtocolException(
                            "SCEP signing " + op.state().name().toLowerCase(java.util.Locale.ROOT));
                    default -> { /* still pending */ }
                }
            }
            Thread.sleep(SIGNING_POLL_INTERVAL_MS); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
        }
        throw new ScepProtocolException("SCEP signing timed out");
    }

    private List<X509Certificate> caChain(PkiId authorityId) throws ScepProtocolException {
        PkiRepository repository = realm.session().repository();
        CaRecord authority = repository.authority(authorityId)
                .orElseThrow(() -> new ScepProtocolException(
                        "SCEP CA authority is unavailable: " + authorityId));
        IssuerChainPath path = repository.chainPath(authority.issuanceChainPathId())
                .orElseThrow(() -> new ScepProtocolException(
                        "SCEP CA chain path is unavailable: " + authorityId));
        List<X509Certificate> chain = new ArrayList<>();
        for (PkiId credId : path.orderedCredentialIds()) {
            try (PkiRepositoryContent content = repository.openCredential(credId);
                 InputStream in = content.openStream()) {
                chain.add(parseCert(in.readAllBytes()));
            } catch (IOException e) {
                throw new ScepProtocolException("SCEP CA certificate is unreadable", e);
            }
        }
        return List.copyOf(chain);
    }

    private static X509Certificate parseCert(byte[] der) throws ScepProtocolException {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new ScepProtocolException("Cannot parse X.509 certificate", e);
        }
    }

    private static KeyPair generateRaKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate SCEP RA key pair", e);
        }
    }

    private static X509Certificate buildRaCert(KeyPair raKeyPair) {
        try {
            Instant now = Instant.now();
            X500Principal subject = new X500Principal("CN=SCEP-RA, O=ZeroEcho");
            AlgorithmIdentifier sigAlg = AlgorithmIdentifier.derNull(OID_SHA256_WITH_RSA);
            zeroecho.pkix.cert.CertificateBuilder builder = Pkix.certificateBuilder()
                    .subject(subject)
                    .issuer(subject)
                    .publicKey(raKeyPair.getPublic())
                    .serialNumber(BigInteger.valueOf(1L))
                    .validity(now, now.plus(3650, ChronoUnit.DAYS));
            return builder.build(Pkix.signer(raKeyPair.getPrivate(), sigAlg));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build SCEP RA self-signed certificate", e);
        }
    }
}
