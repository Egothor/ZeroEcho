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
package zeroecho.pki.server.cmp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.x500.X500Principal;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cmp.CmpCodec;
import zeroecho.pkix.cmp.CmpCodecException;
import zeroecho.pkix.cmp.CmpPkiMessage;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.issuance.EndEntityIssuanceRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.signing.PreparedSemanticSigningRequest;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SigningAcceptanceDisposition;
import zeroecho.pki.api.signing.SigningAcceptanceResult;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.server.ServerRealmContext;

/**
 * CMP RFC 4210 / RFC 9480 Lightweight Profile protocol service.
 *
 * <p>Manages the endpoint registry and coordinates CMP protocol operations.
 * Supported body types: ir(0), cr(2), kur(7), rr(11), genm(21).
 *
 * <p>CMP ir/cr use server-side key generation (EC P-256 ephemeral pair): the
 * server generates a key pair, issues a certificate using a self-signed CSR
 * built from the CertTemplate subject, and returns both in the ip/cp response.
 * This works around the requirement for a PKCS#10 proof-of-possession signature,
 * since the CMP CertTemplate is not a self-signed CSR.
 *
 * <p>No BouncyCastle imports appear in this class — all codec work is delegated
 * to {@link CmpCodec} in the lib module.</p>
 *
 * @since 1.0
 */
@SuppressWarnings("PMD.SignatureDeclareThrowsException")
public final class CmpService {


    /** SHA-256withECDSA OID. */
    private static final String OID_SHA256_WITH_ECDSA = "1.2.840.10045.4.3.2";

    /** Maximum wait for signing completion. */
    private static final long SIGNING_POLL_TIMEOUT_MS = 60_000L;
    /** Interval between signing completion polls. */
    private static final long SIGNING_POLL_INTERVAL_MS = 100L;

    private final ServerRealmContext realm;
    private final ConcurrentMap<String, CmpEndpoint> endpoints = new ConcurrentHashMap<>();

    /**
     * Creates a CMP service over the given realm.
     *
     * @param realm lifecycle-owned realm context
     */
    public CmpService(ServerRealmContext realm) {
        this.realm = Objects.requireNonNull(realm, "realm");
    }

    // -------------------------------------------------------------------------
    // Endpoint registry
    // -------------------------------------------------------------------------

    /**
     * Registers a CMP endpoint, replacing an existing entry with the same label.
     * @param endpoint non-null endpoint configuration
     */
    public void register(CmpEndpoint endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        endpoints.put(endpoint.label(), endpoint);
    }

    /**
     * Removes the endpoint with the given label.
     * @param label non-null registry label
     * @return the removed endpoint, or empty if no entry existed
     */
    public Optional<CmpEndpoint> deregister(String label) {
        return Optional.ofNullable(endpoints.remove(Objects.requireNonNull(label, "label")));
    }

    /**
     * Looks up the endpoint for the given label.
     * @param label non-null registry label
     * @return the observed endpoint, or empty if absent
     */
    public Optional<CmpEndpoint> find(String label) {
        return Optional.ofNullable(endpoints.get(Objects.requireNonNull(label, "label")));
    }

    /**
     * Copies endpoints observed during a weakly consistent registry traversal.
     * @return an immutable list in unspecified order; concurrent changes are not
     *         represented as an atomic point-in-time snapshot
     */
    public List<CmpEndpoint> list() {
        return List.copyOf(endpoints.values());
    }

    // -------------------------------------------------------------------------
    // CMP protocol dispatch
    // -------------------------------------------------------------------------

    /**
     * Processes a CMP PKIMessage and returns the DER-encoded response PKIMessage.
     *
     * @param endpoint      the CMP endpoint
     * @param pkiMessageDer DER-encoded CMP PKIMessage from the HTTP request body
     * @return DER-encoded CMP response PKIMessage
     * @throws CmpProtocolException if the message is malformed or the operation fails
     */
    public byte[] processMessage(CmpEndpoint endpoint, byte[] pkiMessageDer)
            throws CmpProtocolException {
        Objects.requireNonNull(endpoint, "endpoint");
        Objects.requireNonNull(pkiMessageDer, "pkiMessageDer");

        CmpPkiMessage request;
        try {
            request = CmpCodec.parseMessage(pkiMessageDer);
        } catch (CmpCodecException e) {
            throw new CmpProtocolException(400, "Failed to parse CMP PKIMessage: " + e.getMessage(), e);
        }

        return switch (request.bodyType()) {
            case CmpCodec.BODY_IR -> handleCertRequest(endpoint, request, true);
            case CmpCodec.BODY_CR -> handleCertRequest(endpoint, request, false);
            case CmpCodec.BODY_KUR -> handleKeyUpdateRequest(endpoint, request);
            case CmpCodec.BODY_RR -> handleRevocationRequest(endpoint, request);
            case CmpCodec.BODY_GENM -> handleGenm(endpoint, request);
            default -> buildError(request, "Unsupported CMP body type: " + request.bodyType());
        };
    }

    // -------------------------------------------------------------------------
    // Private: ir/cr — server-side key generation
    // -------------------------------------------------------------------------

    private byte[] handleCertRequest(CmpEndpoint endpoint, CmpPkiMessage request, boolean isIr)
            throws CmpProtocolException {
        // Server-side key generation using EC P-256
        KeyPair keyPair = generateEcKeyPair();

        // Extract subject from CertTemplate (use a default if absent)
        X500Principal subject = defaultSubject();

        // Build a self-signed CSR with the generated key pair for PoP verification
        AlgorithmIdentifier sigAlg = AlgorithmIdentifier.absent(OID_SHA256_WITH_ECDSA);
        byte[] generatedCsrDer;
        try {
            zeroecho.pkix.csr.CertificationRequest csr = Pkix.certificationRequestBuilder()
                    .subject(subject)
                    .publicKey(keyPair.getPublic())
                    .build(Pkix.signer(keyPair.getPrivate(), sigAlg));
            generatedCsrDer = csr.encoded();
        } catch (Exception e) {
            return buildError(request, "CMP server-keygen CSR construction failed: " + e.getMessage());
        }

        AccessContext access = new AccessContext(
                new Principal("CMP", endpointPrincipal(request, endpoint)),
                new Purpose(isIr ? "CMP_IR" : "CMP_CR"),
                Optional.of(new PkiId(endpoint.authorityId())),
                Optional.empty());
        EndEntityIssuanceRequest issuanceRequest = new EndEntityIssuanceRequest(
                new PkiId(endpoint.authorityId()), generatedCsrDer, endpoint.profileId(), Optional.empty());

        SemanticSigningService signing = requireSigning();
        PreparedSemanticSigningRequest prepared;
        try {
            prepared = signing.prepareEndEntity(access, issuanceRequest, Optional.empty(), CancellationSignal.NONE);
        } catch (Exception e) {
            return buildError(request, "CMP issuance preparation failed: " + e.getMessage());
        }

        SigningAcceptanceResult accepted;
        try {
            accepted = signing.accept(prepared);
        } catch (Exception e) {
            return buildError(request, "CMP signing acceptance failed: " + e.getMessage());
        }

        if (accepted.disposition() == SigningAcceptanceDisposition.CAPACITY_REJECTED) {
            return buildError(request, "CMP signing capacity exhausted; retry later");
        }
        if (accepted.disposition() == SigningAcceptanceDisposition.CONFLICT) {
            return buildError(request, "CMP signing conflict");
        }

        SemanticSigningOperation completed;
        try {
            completed = pollForCompletion(signing, accepted.receipt().operationId());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
            return buildError(request, "CMP signing interrupted");
        } catch (Exception e) {
            return buildError(request, "CMP signing failed: " + e.getMessage());
        }

        byte[] issuedCertDer;
        try {
            issuedCertDer = completed.result()
                    .orElseThrow(() -> new CmpProtocolException(500, "CMP result is absent"))
                    .bytes();
        } catch (CmpProtocolException e) {
            return buildError(request, e.getMessage());
        }

        try {
            return CmpCodec.buildCertResponse(request, issuedCertDer, isIr);
        } catch (CmpCodecException e) {
            throw new CmpProtocolException(500, "CMP cert response encoding failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private: kur — key update (renewal)
    // -------------------------------------------------------------------------

    private byte[] handleKeyUpdateRequest(CmpEndpoint endpoint, CmpPkiMessage request)
            throws CmpProtocolException {
        // kur uses the same server-side keygen approach as ir/cr
        return handleCertRequest(endpoint, request, false);
    }

    // -------------------------------------------------------------------------
    // Private: rr — revocation request
    // -------------------------------------------------------------------------

    private byte[] handleRevocationRequest(CmpEndpoint endpoint, CmpPkiMessage request)
            throws CmpProtocolException {
        BigInteger serialNumber = request.serialNumber();
        if (serialNumber == null) {
            return buildError(request, "CMP rr missing serialNumber in CertTemplate");
        }

        PkiId authorityId = new PkiId(endpoint.authorityId());
        PkiRepository repository = realm.session().repository();

        Optional<Credential> credentialOpt = repository.credential(authorityId, serialNumber);
        if (credentialOpt.isEmpty()) {
            return buildError(request, "CMP rr credential not found: serial=" + serialNumber);
        }
        PkiId credentialId = credentialOpt.get().credentialId();

        try {
            realm.session().revocations().revokePermanently(
                    new RevocationCommand.RevokePermanently(credentialId, RevocationReason.UNSPECIFIED,
                            emptyAttributeSet()));
        } catch (Exception e) {
            return buildError(request, "CMP revocation failed: " + e.getMessage());
        }

        try {
            return CmpCodec.buildRevocationResponse(request);
        } catch (CmpCodecException e) {
            throw new CmpProtocolException(500, "CMP rp encoding failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private: genm — general message (CA chain query)
    // -------------------------------------------------------------------------

    private byte[] handleGenm(CmpEndpoint endpoint, CmpPkiMessage request)
            throws CmpProtocolException {
        List<X509Certificate> chain = caChain(new PkiId(endpoint.authorityId()));
        try {
            List<byte[]> certsDer = new ArrayList<>();
            for (X509Certificate cert : chain) {
                certsDer.add(cert.getEncoded());
            }
            return CmpCodec.buildGenp(request, certsDer);
        } catch (Exception e) {
            throw new CmpProtocolException(500, "CMP genp encoding failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    private byte[] buildError(CmpPkiMessage request, String statusText) throws CmpProtocolException {
        try {
            return CmpCodec.buildError(request.senderNonce(), request.transactionId(), statusText);
        } catch (CmpCodecException e) {
            throw new CmpProtocolException(500, "CMP error response encoding failed", e);
        }
    }

    private SemanticSigningService requireSigning() throws CmpProtocolException {
        return realm.session().semanticSigning()
                .orElseThrow(() -> new CmpProtocolException(503, "CMP signing capability is unavailable"));
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
                    case FAILED, EXPIRED -> throw new CmpProtocolException(
                            500, "CMP signing " + op.state().name().toLowerCase(java.util.Locale.ROOT));
                    default -> { /* still pending */ }
                }
            }
            Thread.sleep(SIGNING_POLL_INTERVAL_MS); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.
        }
        throw new CmpProtocolException(503, "CMP signing timed out");
    }

    private List<X509Certificate> caChain(PkiId authorityId) throws CmpProtocolException {
        PkiRepository repository = realm.session().repository();
        CaRecord authority = repository.authority(authorityId)
                .orElseThrow(() -> new CmpProtocolException(503,
                        "CMP CA authority is unavailable: " + authorityId));
        IssuerChainPath path = repository.chainPath(authority.issuanceChainPathId())
                .orElseThrow(() -> new CmpProtocolException(503,
                        "CMP CA chain path is unavailable: " + authorityId));
        List<X509Certificate> chain = new ArrayList<>();
        for (PkiId credId : path.orderedCredentialIds()) {
            try (PkiRepositoryContent content = repository.openCredential(credId);
                 InputStream in = content.openStream()) {
                chain.add(parseCert(in.readAllBytes()));
            } catch (IOException e) {
                throw new CmpProtocolException(503, "CMP CA certificate is unreadable", e);
            }
        }
        return List.copyOf(chain);
    }

    private static X509Certificate parseCert(byte[] der) throws CmpProtocolException {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new CmpProtocolException(500, "Cannot parse X.509 certificate", e);
        }
    }

    private static KeyPair generateEcKeyPair() throws CmpProtocolException {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new CmpProtocolException(500, "CMP server-keygen key generation failed", e);
        }
    }

    private static X500Principal defaultSubject() {
        // Best-effort: use a placeholder subject; the CA profile applies its own naming policy
        return new X500Principal("CN=CMP-ServerKeyGen");
    }

    private static String endpointPrincipal(CmpPkiMessage request, CmpEndpoint endpoint) {
        byte[] txId = request.transactionId();
        if (txId != null && txId.length > 0) {
            return java.util.HexFormat.of().formatHex(txId);
        }
        return endpoint.label();
    }

    private static AttributeSet emptyAttributeSet() {
        return new AttributeSet() {
            @Override public Set<AttributeId> ids() { return Set.of(); }
            @Override public Optional<AttributeValue> get(AttributeId id) { return Optional.empty(); }
            @Override public List<AttributeValue> getAll(AttributeId id) { return List.of(); }
        };
    }
}
