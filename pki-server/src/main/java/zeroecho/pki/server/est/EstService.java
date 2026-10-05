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
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
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
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.issuance.EndEntityRenewalRequest;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
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
 * <p>Endpoint registration is thread-safe via {@link ConcurrentHashMap}; operation
 * methods are stateless with respect to the endpoint registry and safe to call concurrently.</p>
 *
 * @since 1.0
 */
@SuppressWarnings("PMD.AvoidCatchingGenericException")
public final class EstService {
    private static final String TEXT_ENDPOINT = "endpoint";


    /** SHA-256withRSA (PKCS#1 v1.5) OID. */
    private static final String OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    /** SHA-256withECDSA OID. */
    private static final String OID_SHA256_WITH_ECDSA = "1.2.840.10045.4.3.2";

    /** EC P-256 curve name. */
    private static final String EC_P256 = "secp256r1";
    /** Default RSA key size in bits when not otherwise constrained by policy. */
    private static final int RSA_DEFAULT_BITS = 2048;
    /** Maximum wait for signing completion before returning 503. */
    private static final long SIGNING_POLL_TIMEOUT_MS = 60_000L;
    /** Interval between signing-completion polls. */
    private static final long SIGNING_POLL_INTERVAL_MS = 100L;

    private final ServerRealmContext realm;
    private final ConcurrentMap<String, EstEndpoint> endpoints = new ConcurrentHashMap<>();

    /**
     * Creates an EST service over the given realm.
     *
     * @param realm lifecycle-owned realm context
     */
    public EstService(ServerRealmContext realm) {
        this.realm = Objects.requireNonNull(realm, "realm");
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
        endpoints.put(endpoint.label(), endpoint);
    }

    /**
     * Removes the endpoint with the given label.
     *
     * @param label URL-safe endpoint label
     * @return the removed endpoint, or empty if absent
     */
    public Optional<EstEndpoint> deregister(String label) {
        return Optional.ofNullable(endpoints.remove(Objects.requireNonNull(label, "label")));
    }

    /**
     * Returns the endpoint for the given label.
     *
     * @param label URL-safe endpoint label
     * @return the endpoint, or empty when not registered
     */
    public Optional<EstEndpoint> find(String label) {
        return Optional.ofNullable(endpoints.get(Objects.requireNonNull(label, "label")));
    }

    /**
     * Returns an immutable snapshot of all registered endpoints.
     *
     * @return current endpoint list
     */
    public List<EstEndpoint> list() {
        return List.copyOf(endpoints.values());
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
     * issues a certificate, and returns the issued certificate + chain as MIME-base64-encoded
     * CMS certs-only.
     *
     * @param endpoint   the EST endpoint
     * @param csrBody    raw PKCS#10 CSR bytes (DER or PEM); self-signature must be valid
     * @param clientCert authenticated mTLS client certificate
     * @return MIME-base64-encoded CMS certs-only DER
     * @throws EstProtocolException if the CSR is invalid, issuance fails, or times out
     */
    public byte[] simpleenroll(EstEndpoint endpoint, byte[] csrBody, X509Certificate clientCert)
            throws EstProtocolException {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        Objects.requireNonNull(csrBody, "csrBody");
        Objects.requireNonNull(clientCert, "clientCert");

        byte[] csrDer = requireValidCsr(csrBody);
        AccessContext access = estAccess(clientCert, "EST_SIMPLEENROLL", endpoint);
        EndEntityIssuanceRequest request = new EndEntityIssuanceRequest(
                new PkiId(endpoint.authorityId()), csrDer, endpoint.profileId(), Optional.empty());
        return issueAndEncode(access, request, endpoint);
    }

    /**
     * Performs EST {@code simplereenroll} (RFC 7030 section 4.2.2): renews the client's
     * certificate using the current logical profile, returning the renewed certificate chain
     * as MIME-base64-encoded CMS certs-only.
     *
     * @param endpoint   the EST endpoint
     * @param csrBody    renewal PKCS#10 CSR bytes (DER or PEM); self-signature must be valid
     * @param clientCert authenticated mTLS client certificate (the predecessor)
     * @return MIME-base64-encoded CMS certs-only DER
     * @throws EstProtocolException if renewal fails or times out
     */
    public byte[] simplereenroll(EstEndpoint endpoint, byte[] csrBody, X509Certificate clientCert)
            throws EstProtocolException {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        Objects.requireNonNull(csrBody, "csrBody");
        Objects.requireNonNull(clientCert, "clientCert");

        requireValidCsr(csrBody);
        AccessContext access = estAccess(clientCert, "EST_SIMPLEREENROLL", endpoint);
        PkiId existingCredentialId = credentialIdFor(clientCert);
        EndEntityRenewalRequest request = new EndEntityRenewalRequest(existingCredentialId, Optional.empty());

        SemanticSigningService signing = requireSigning("renewal");
        PreparedSemanticSigningRequest prepared = signing.prepareRenewal(
                access, request, Optional.empty(), CancellationSignal.NONE);
        SigningAcceptanceResult accepted = acceptOrThrow(signing, prepared, "renewal");
        SemanticSigningOperation completed = pollForCompletion(signing, accepted.receipt().operationId());
        return EstCmsCodec.encodeCertsOnly(buildIssuedChain(completed, new PkiId(endpoint.authorityId())));
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
     * Performs EST {@code serverkeygen} (RFC 7030 section 4.4): generates a server-side key
     * pair, issues a certificate using the template CSR subject, and returns both as a
     * {@code multipart/mixed} response.
     *
     * <p>The private key is encrypted for the mTLS client certificate's public key using
     * CMS EnvelopedData (AES-256-GCM). The raw private key bytes are zeroed after encryption.</p>
     *
     * @param endpoint   the EST endpoint
     * @param csrBody    template PKCS#10 CSR bytes (subject and extensions used as template)
     * @param clientCert authenticated mTLS client certificate (recipient of encrypted key)
     * @return structured response with encrypted private key, certificate chain, and boundary
     * @throws EstProtocolException if serverkeygen is disabled, the algorithm is unsupported,
     *                              issuance fails, or the operation times out
     */
    public EstServerKeygenResponse serverkeygen(EstEndpoint endpoint, byte[] csrBody,
            X509Certificate clientCert) throws EstProtocolException {
        Objects.requireNonNull(endpoint, TEXT_ENDPOINT);
        Objects.requireNonNull(csrBody, "csrBody");
        Objects.requireNonNull(clientCert, "clientCert");

        KeygenPolicy policy = endpoint.keygen();
        if (!policy.enabled()) {
            throw new EstProtocolException(404, "Server-side key generation is not enabled on this EST endpoint");
        }

        // Parse template CSR to extract subject name.
        CertificationRequest template;
        try {
            template = Pkix.parseCsr(csrBody);
        } catch (CertificationRequestException failure) {
            throw new EstProtocolException(400,
                    "EST serverkeygen template CSR is invalid: " + failure.getMessage(), failure);
        }
        X500Principal subject = template.subject();

        // Generate key pair using the first permitted algorithm.
        String jcaAlg = policy.permittedAlgorithms().getFirst();
        KeyPair keyPair = generateKeyPair(jcaAlg, policy.maximumKeySizeBits());

        // Build a self-signed CSR with the generated key pair and the template subject.
        AlgorithmIdentifier sigAlg = signingAlgorithmFor(jcaAlg);
        byte[] generatedCsrDer;
        try {
            CertificationRequest generated = Pkix.certificationRequestBuilder()
                    .subject(subject)
                    .publicKey(keyPair.getPublic())
                    .build(Pkix.signer(keyPair.getPrivate(), sigAlg));
            generatedCsrDer = generated.encoded();
        } catch (Exception failure) {
            throw new EstProtocolException(500, "EST serverkeygen CSR construction failed", failure);
        }

        // Issue the certificate using the generated CSR.
        AccessContext access = estAccess(clientCert, "EST_SERVERKEYGEN", endpoint);
        EndEntityIssuanceRequest request = new EndEntityIssuanceRequest(
                new PkiId(endpoint.authorityId()), generatedCsrDer, endpoint.profileId(), Optional.empty());
        List<X509Certificate> chain = issueAndBuildChain(access, request, endpoint);

        // Encrypt private key for the client certificate, then zero the raw bytes.
        byte[] pkcs8Der = keyPair.getPrivate().getEncoded();
        try {
            byte[] encryptedKeyBase64 = EstCmsCodec.encryptPrivateKey(pkcs8Der, clientCert);
            byte[] certsCmsBase64 = EstCmsCodec.encodeCertsOnly(chain);
            byte[][] multipart = EstCmsCodec.buildServerKeygenMultipart(encryptedKeyBase64, certsCmsBase64);
            return new EstServerKeygenResponse(multipart[0], certsCmsBase64,
                    new String(multipart[1], StandardCharsets.US_ASCII));
        } finally {
            Arrays.fill(pkcs8Der, (byte) 0);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private byte[] requireValidCsr(byte[] csrBody) throws EstProtocolException {
        try {
            return Pkix.parseCsr(csrBody).encoded();
        } catch (CertificationRequestException failure) {
            throw new EstProtocolException(400, "EST CSR is invalid: " + failure.getMessage(), failure);
        }
    }

    private byte[] issueAndEncode(AccessContext access, EndEntityIssuanceRequest request,
            EstEndpoint endpoint) throws EstProtocolException {
        return EstCmsCodec.encodeCertsOnly(issueAndBuildChain(access, request, endpoint));
    }

    private List<X509Certificate> issueAndBuildChain(AccessContext access,
            EndEntityIssuanceRequest request, EstEndpoint endpoint) throws EstProtocolException {
        SemanticSigningService signing = requireSigning("issuance");
        PreparedSemanticSigningRequest prepared = signing.prepareEndEntity(
                access, request, Optional.empty(), CancellationSignal.NONE);
        SigningAcceptanceResult accepted = acceptOrThrow(signing, prepared, "issuance");
        SemanticSigningOperation completed = pollForCompletion(signing, accepted.receipt().operationId());
        return buildIssuedChain(completed, new PkiId(endpoint.authorityId()));
    }

    private SigningAcceptanceResult acceptOrThrow(SemanticSigningService signing,
            PreparedSemanticSigningRequest prepared, String context) throws EstProtocolException {
        SigningAcceptanceResult accepted;
        try {
            accepted = signing.accept(prepared);
        } catch (RuntimeException failure) {
            throw new EstProtocolException(503, "EST " + context + " signing acceptance failed", failure);
        }
        if (accepted.disposition() == SigningAcceptanceDisposition.CAPACITY_REJECTED) {
            throw new EstProtocolException(503, "EST " + context + " signing capacity exhausted");
        }
        if (accepted.disposition() == SigningAcceptanceDisposition.CONFLICT) {
            throw new EstProtocolException(409, "EST " + context + " signing correlation conflict");
        }
        return accepted;
    }

    private SemanticSigningService requireSigning(String context) throws EstProtocolException {
        return realm.session().semanticSigning()
                .orElseThrow(() -> new EstProtocolException(503, "EST " + context + " capability is unavailable"));
    }

    private SemanticSigningOperation pollForCompletion(SemanticSigningService signing,
            PkiId operationId) throws EstProtocolException {
        long deadline = System.currentTimeMillis() + SIGNING_POLL_TIMEOUT_MS;
        while (System.currentTimeMillis() < deadline) {
            Optional<SemanticSigningOperation> snapshot = signing.find(operationId);
            if (snapshot.isPresent()) {
                SemanticSigningOperation op = snapshot.get();
                switch (op.state()) {
                    case COMPLETED -> { return op; }
                    case FAILED, EXPIRED -> {
                        String detail = op.detailCode().map(c -> ": " + c).orElse("");
                        throw new EstProtocolException(500, "EST signing " + op.state().name().toLowerCase(java.util.Locale.ROOT) + detail);
                    }
                    default -> { /* still pending */ }
                }
            }
            try {
                Thread.sleep(SIGNING_POLL_INTERVAL_MS); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
                throw new EstProtocolException(503, "EST signing wait interrupted", interrupted);
            }
        }
        throw new EstProtocolException(503,
                "EST signing timed out after " + (SIGNING_POLL_TIMEOUT_MS / 1000) + "s");
    }

    private List<X509Certificate> buildIssuedChain(SemanticSigningOperation completed,
            PkiId authorityId) throws EstProtocolException {
        byte[] issuedDer = completed.result()
                .orElseThrow(() -> new EstProtocolException(500, "EST signing result is absent"))
                .bytes();
        X509Certificate issued = parseCertificate(issuedDer);
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(issued);
        chain.addAll(caChain(authorityId));
        return List.copyOf(chain);
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

    private static X509Certificate parseCertificate(byte[] der) throws EstProtocolException {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception failure) {
            throw new EstProtocolException(500, "EST certificate parsing failed", failure);
        }
    }

    private static AccessContext estAccess(X509Certificate clientCert, String purpose,
            EstEndpoint endpoint) {
        String principalName = clientCert.getSubjectX500Principal().getName();
        return new AccessContext(new Principal("EST", principalName), new Purpose(purpose),
                Optional.of(new PkiId(endpoint.authorityId())), Optional.empty());
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
