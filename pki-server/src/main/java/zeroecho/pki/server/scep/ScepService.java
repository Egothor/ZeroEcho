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
package zeroecho.pki.server.scep;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.scep.ScepCodec;
import zeroecho.pkix.scep.ScepCodecException;
import zeroecho.pkix.scep.ScepPkiMessage;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.CertificateIdentityEvidence;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.server.enrollment.EnrollmentRuntime;
import zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;

/**
 * SCEP enrollment adapter with provisioned authority-scoped RA custody and durable
 * enrollment continuation. CMS verification precedes credential selection and
 * decryption; the shared coordinator owns approval, signing and recovery.
 * No request, private key or transaction state is retained in this service.
 */
public final class ScepService {
    private final ServerRealmContext realm;
    private final EnrollmentEndpointRegistry endpoints;

    /** Creates a stateless adapter.

     * @param realm lifecycle-owned realm context

     */
    public ScepService(ServerRealmContext realm) {
        this.realm = Objects.requireNonNull(realm, "realm");
        endpoints = Objects.requireNonNull(realm.enrollmentEndpoints(), "enrollmentEndpoints");
    }

    /** Registers or replaces an endpoint.

     * @param endpoint validated configuration

     */
    public void register(ScepEndpoint endpoint) { endpoints.register(Objects.requireNonNull(endpoint, "endpoint")); }

    /** Removes an endpoint.

     * @param label endpoint label
     * @return removed endpoint, if present
     */
    public Optional<ScepEndpoint> deregister(String label) {
        return endpoints.deregister(EnrollmentEndpointRegistry.Protocol.SCEP, label).map(value -> (ScepEndpoint) value);
    }

    /** Finds an endpoint.

     * @param label endpoint label
     * @return current endpoint, if present
     */
    public Optional<ScepEndpoint> find(String label) {
        return endpoints.find(EnrollmentEndpointRegistry.Protocol.SCEP, label).map(value -> (ScepEndpoint) value);
    }

    /** Collects current endpoints.

     * @return immutable endpoints from bounded store pages

     */
    public List<ScepEndpoint> list() {
        return endpoints.list(EnrollmentEndpointRegistry.Protocol.SCEP).stream().map(value -> (ScepEndpoint) value).toList();
    }

    /**
     * Public RA advertisement with explicit media type.
     * @param contentType RFC 8894 media type
     * @param body certificates-only CMS bytes
     */
    public record CaCertificateResponse(String contentType, byte[] body) {
        /** Validates and copies the response body. */
        public CaCertificateResponse {
            Objects.requireNonNull(contentType, "contentType"); body = body.clone();
        }
        /** Copies the response.
         * @return independent encoded certificate set
         */
        @Override public byte[] body() { return body.clone(); }
        /** @return description without certificate data */
        @Override public String toString() { return "CaCertificateResponse[certificates-only]"; }
    }

    /**
     * Advertises the actual active RA and its exact issuing CA chain.
     * @param endpoint current endpoint
     * @return typed degenerate CMS response
     * @throws ScepProtocolException if configuration or custody is unavailable
     */
    public CaCertificateResponse getCaCert(ScepEndpoint endpoint) throws ScepProtocolException {
        try {
            endpoints.requireCurrent(endpoint);
            EnrollmentRuntime runtime = runtime();
            String id = runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.SCEP, endpoint.authorityId());
            try (EnrollmentRuntime.CredentialLease lease = runtime.acquire(id)) {
                List<byte[]> chain = new ArrayList<>();
                for (X509Certificate certificate : lease.responseChain()) {
                    chain.add(certificate.getEncoded());
                }
                return new CaCertificateResponse("application/x-x509-ca-ra-cert", ScepCodec.buildDegenerateCertsCms(chain));
            }
        } catch (Exception unavailable) { throw new ScepProtocolException(503, "SCEP CA advertisement is unavailable"); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    /** Returns the same provisioned certificate set as GetCACert.
     * @param endpoint current endpoint
     * @return certificates-only CMS
     * @throws ScepProtocolException if custody is unavailable
     */
    public byte[] getCaCertChain(ScepEndpoint endpoint) throws ScepProtocolException { return getCaCert(endpoint).body(); }

    /** Advertises implemented capabilities.

     * @return ASCII capability list

     */
    public byte[] getCaCaps() {
        return "POSTPKIOperation\nSHA-256\nAES\n".getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Processes authenticated PKCSReq or GetCertInitial with durable replay and
     * frozen credential selection. A retry may deliver a retained completed result.
     * @param endpoint routed endpoint
     * @param messageData bounded encoded CMS request
     * @return signed CertRep, pending, failure or encrypted completed certificate
     * @throws ScepProtocolException for unauthenticated input or unavailable custody
     */
    public byte[] processPkiOperation(ScepEndpoint endpoint, byte[] messageData) throws ScepProtocolException {
        return processPkiOperation(endpoint, messageData, () -> Thread.currentThread().isInterrupted()); // NOPMD DoNotUseThreads - Observes caller cancellation while owning a bounded lease; this standalone component creates no thread.
    }

    /**
     * Processes a request with cancellation before durable signing admission.
     * @param endpoint routed endpoint
     * @param messageData bounded encoded CMS request
     * @param cancellation request cancellation signal
     * @return signed CertRep
     * @throws ScepProtocolException for invalid input or unavailable processing
     */
    public byte[] processPkiOperation(ScepEndpoint endpoint, byte[] messageData, CancellationSignal cancellation)
            throws ScepProtocolException {
        Objects.requireNonNull(endpoint, "endpoint"); Objects.requireNonNull(cancellation, "cancellation");
        ScepCodec.VerifiedRequest verified;
        try { verified = ScepCodec.verifyRequest(messageData); }
        catch (ScepCodecException invalid) { throw new ScepProtocolException(400, "Invalid SCEP message"); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        try {
            CertificateIdentityEvidence evidence = CertificateIdentityEvidence.fromCertificate(realm.configuration().realmId(),
                    verified.requesterCertificate());
            EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.SCEP_SIGNER,
                    evidence.certificateSha256(), IssuanceExecutionEvidence.Authentication.SCEP_CMS, Optional.of(evidence),
                    Optional.of(evidence.canonicalKeySha256()), evidence.legacySpkiSha256(),
                    new EnrollmentIdentityAliases.Snapshot(realm.configuration().realmId(), Set.of()));
            String transactionHash = digest(verified.transactionId().getBytes(StandardCharsets.US_ASCII));
            EnrollmentCoordinator coordinator = realm.enrollmentCoordinator().orElseThrow(); // NOPMD CloseResource - Borrowed realm coordinator; the realm owns its shutdown.
            Optional<EnrollmentTransaction> retained = coordinator.find(EnrollmentTransaction.Protocol.SCEP, endpoint.label(),
                    requester.type(), requester.actorId(), transactionHash, EnrollmentTransaction.Operation.ISSUE);
            EnrollmentRuntime runtime = runtime();
            String credential = retained.map(value -> value.intent().source().credentialId().orElseThrow()).orElseGet(
                    () -> runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.SCEP, endpoint.authorityId()));
            try (EnrollmentRuntime.CredentialLease lease = runtime.acquire(credential)) {
                X509Certificate ra = lease.responseChain().getFirst();
                PrivateKey key = lease.privateKey();
                ScepPkiMessage request = ScepCodec.decryptRequest(verified, ra, key);
                if (retained.isPresent()) {
                    requireRetained(retained.orElseThrow(), requester, lease);
                }
                EnrollmentTransaction value;
                if (request.messageType() == ScepCodec.MSG_GET_CERT_INITIAL) {
                    if (retained.isEmpty()) {
                        return failure(request, ra, key);
                    }
                    value = retained.orElseThrow();
                    byte[] csr = originalRequest(value);
                    ScepCodec.requireIssuerAndSubject(request.innerContent(), lease.responseChain().get(1).getSubjectX500Principal(),
                            Pkix.parseCsr(csr).subject());
                } else {
                    String expected;
                    if (retained.isEmpty()) {
                        EnrollmentEndpointRegistry.Snapshot snapshot = endpoints.requireCurrent(endpoint);
                        if (!challengeMatches(ScepCodec.extractChallengePassword(request.innerContent()), endpoint.challengePasswordHash())) {
                            return failure(request, ra, key);
                        }
                        expected = snapshot.commitment();
                    } else {
                        expected = retained.orElseThrow().intent().source().commitment();
                    }
                    value = coordinator.admit(new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.SCEP, endpoint.label(), requester,
                            transactionHash, EnrollmentTransaction.Operation.ISSUE,
                            new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, request.innerContent()), Optional.empty(), Optional.empty()), expected);
                    requireRetained(value, requester, lease);
                }
                value = coordinator.dispatch(value.id(), cancellation);
                return switch (value.state()) {
                    case ISSUED -> ScepCodec.buildCertRepSuccess(request.transactionId(), request.senderNonce(),
                            issuedCertificate(value), request.requesterCert(), ra, key);
                    case REJECTED, EXPIRED, FAILED -> failure(request, ra, key);
                    default -> ScepCodec.buildCertRepPending(request.transactionId(), request.senderNonce(), ra, key);
                };
            }
        } catch (ScepCodecException | IllegalArgumentException invalid) {
            throw new ScepProtocolException(400, "Invalid SCEP enrollment request"); // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        } catch (Exception unavailable) { throw new ScepProtocolException(503, "SCEP enrollment is unavailable"); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    private static void requireRetained(EnrollmentTransaction value, EnrollmentTransaction.Requester requester,
            EnrollmentRuntime.CredentialLease lease) {
        EnrollmentRuntimeConfiguration.CredentialSet credential = lease.configuration();
        if (!value.intent().requester().certificate().equals(requester.certificate())
                || !value.intent().requester().canonicalKeySha256().equals(requester.canonicalKeySha256())
                || !value.intent().source().credentialId().equals(Optional.of(credential.credentialId()))
                || !value.intent().authorityId().value().equals(credential.authorityId())
                || !value.intent().issuerId().value().equals(credential.issuerId())
                || !value.intent().pathId().value().equals(credential.chainPathId())) {
            throw new IllegalStateException("SCEP binding unavailable");
        }
    }

    private byte[] originalRequest(EnrollmentTransaction value) {
        zeroecho.pki.api.CertificationRequestService requests = realm.session().requests().orElseThrow();
        X509EnrollmentPayload payload = requests.encodedX509Request(requests.get(value.intent().requestId()).orElseThrow());
        if (payload.kind() != X509EnrollmentPayload.Kind.PKCS10 || !digest(payload.der()).equals(value.intent().requestSha256())) {
            throw new IllegalStateException("SCEP retained request unavailable");
        }
        return payload.der();
    }

    private byte[] issuedCertificate(EnrollmentTransaction value) throws IOException {
        try (PkiRepositoryContent content = realm.session().repository().openCredential(value.credentialId().orElseThrow());
                InputStream input = content.openStream()) {
            byte[] der = input.readNBytes(1_048_577);
            if (der.length == 0 || der.length > 1_048_576) {
                throw new IOException("SCEP credential size is invalid");
            }
            return der;
        }
    }

    private static byte[] failure(ScepPkiMessage request, X509Certificate ra, PrivateKey key) throws ScepCodecException {
        return ScepCodec.buildCertRepFailure(request.transactionId(), request.senderNonce(), ScepCodec.FAIL_BAD_REQUEST, ra, key);
    }

    private static boolean challengeMatches(String challenge, String expected) {
        return challenge != null && MessageDigest.isEqual(HexFormat.of().parseHex(expected),
                HexFormat.of().parseHex(digest(challenge.getBytes(StandardCharsets.UTF_8))));
    }

    private static String digest(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (java.security.NoSuchAlgorithmException unavailable) { throw new IllegalStateException("SHA-256 unavailable", unavailable); }
    }

    private EnrollmentRuntime runtime() { return realm.enrollmentRuntime().orElseThrow(); }
}
