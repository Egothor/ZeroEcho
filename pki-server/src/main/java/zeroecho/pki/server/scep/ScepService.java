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
import java.util.Arrays;
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
 *
 * <p>The realm, registry and coordinators are borrowed. Each acquired native RA
 * credential lease and repository content stream is closed by the call that opens
 * it; private keys are used within the lease and are not exported by this adapter.
 * Exact original request/wire evidence may contain confidential native attributes.
 * CMS verification and request hashing do not sanitize those contents.</p>
 */
public final class ScepService {
    private final ServerRealmContext realm;
    private final EnrollmentEndpointRegistry endpoints;

    /**
     * Creates a stateless adapter.
     *
     * @param realm lifecycle-owned realm context
     * @throws NullPointerException if the realm or its enrollment registry is null
     */
    public ScepService(ServerRealmContext realm) {
        this.realm = Objects.requireNonNull(realm, "realm");
        endpoints = Objects.requireNonNull(realm.enrollmentEndpoints(), "enrollmentEndpoints");
    }

    /**
     * Checks endpoint policy and runtime bindings without registering it.
     *
     * @param endpoint exact proposed endpoint
     * @throws IllegalStateException if policy or runtime credential bindings are unavailable
     */
    public void validateRegistration(ScepEndpoint endpoint) { endpoints.validateRegistration(endpoint); }

    /**
     * Registers or replaces an endpoint.
     *
     * @param endpoint validated configuration
     * @throws NullPointerException if the endpoint is null
     */
    public void register(ScepEndpoint endpoint) { endpoints.register(Objects.requireNonNull(endpoint, "endpoint")); }

    /**
     * Removes an endpoint.
     *
     * @param label endpoint label
     * @return removed endpoint, if present
     */
    public Optional<ScepEndpoint> deregister(String label) {
        return endpoints.deregister(EnrollmentEndpointRegistry.Protocol.SCEP, label).map(value -> (ScepEndpoint) value);
    }

    /**
     * Finds an endpoint.
     *
     * @param label endpoint label
     * @return current endpoint, if present
     */
    public Optional<ScepEndpoint> find(String label) {
        return endpoints.find(EnrollmentEndpointRegistry.Protocol.SCEP, label).map(value -> (ScepEndpoint) value);
    }

    /**
     * Collects current endpoints.
     *
     * @return immutable endpoints from bounded store pages
     */
    public List<ScepEndpoint> list() {
        return endpoints.list(EnrollmentEndpointRegistry.Protocol.SCEP).stream().map(value -> (ScepEndpoint) value).toList();
    }

    /**
     * Public RA advertisement with explicit media type.
     *
     * @param contentType RFC 8894 media type
     * @param body certificates-only CMS bytes
     */
    public record CaCertificateResponse(String contentType, byte[] body) {
        /**
         * Copies advertisement bytes while retaining the required media-type text.
         *
         * <p>The constructor does not validate a MIME type or parse CMS/certificates.</p>
         *
         * @param contentType supplied non-null media type
         * @param body supplied advertisement bytes; cloned without parsing
         * @throws NullPointerException if either argument is null
         */
        public CaCertificateResponse {
            Objects.requireNonNull(contentType, "contentType"); body = body.clone();
        }
        /**
         * Copies the response.
         *
         * @return independent encoded certificate set
         */
        @Override public byte[] body() { return body.clone(); }
        /**
         * Returns description without certificate data.
         *
         * @return description without certificate data
         */
        @Override public String toString() { return "CaCertificateResponse[certificates-only]"; }
    }

    /**
     * Advertises the actual active RA and its exact issuing CA chain.
     *
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

    /**
     * Returns the same provisioned certificate set as GetCACert.
     *
     * @param endpoint current endpoint
     * @return certificates-only CMS
     * @throws ScepProtocolException if custody is unavailable
     */
    public byte[] getCaCertChain(ScepEndpoint endpoint) throws ScepProtocolException { return getCaCert(endpoint).body(); }

    /**
     * Advertises implemented capabilities.
     *
     * @return ASCII capability list
     */
    public byte[] getCaCaps() {
        return "POSTPKIOperation\nSHA-256\nAES\n".getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * Processes authenticated PKCSReq or GetCertInitial with durable replay and
     * frozen credential selection. A retry may deliver a retained completed result.
     * This overload observes interruption on the calling thread as cancellation.
     *
     * @param endpoint routed endpoint
     * @param messageData bounded encoded CMS request
     * @return signed CertRep, pending, failure or encrypted completed certificate
     * @throws ScepProtocolException for unauthenticated input or unavailable custody
     */
    public byte[] processPkiOperation(ScepEndpoint endpoint, byte[] messageData) throws ScepProtocolException {
        return processPkiOperation(endpoint, messageData, () -> Thread.currentThread().isInterrupted()); // NOPMD DoNotUseThreads - Observes caller cancellation while owning a bounded lease; this standalone component creates no thread.
    }

    /**
     * Processes a CMS request with cancellation before durable signing admission.
     *
     * <p>CMS verification precedes credential selection and decryption. Existing
     * transactions use their retained response credential and requester binding;
     * fresh initial requests check current endpoint/challenge policy before native
     * admission. Polls validate original issuer/subject coordinates. These checks
     * do not replace the coordinator's exact proof/policy/replay admission.</p>
     *
     * <p>A transport cancellation does not erase an accepted transaction. The
     * borrowed credential lease covers decryption and protected CertRep signing
     * and closes on all normal/exceptional paths of this operation.</p>
     *
     * @param endpoint routed endpoint
     * @param messageData bounded encoded CMS request
     * @param cancellation request cancellation signal
     * @return signed CertRep
     * @throws NullPointerException if endpoint or cancellation is null
     * @throws ScepProtocolException for invalid CMS/enrollment input (400) or unavailable processing (503)
     * @throws IllegalArgumentException if the supplied SCEP SDK request differs from its original native
     *         request
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
                    if (retained.isPresent() && retained.orElseThrow().intent().sdkProof().isPresent()) {
                        value = retained.orElseThrow();
                        var sdk = coordinator.retainedSdkIntent(value.intent().sdkProof().orElseThrow().intentId()).orElseThrow();
                        if (!Arrays.equals(sdk.nativeWire().orElseThrow(), messageData) || !Arrays.equals(sdk.originalPayload().der(), request.innerContent())) throw new IllegalArgumentException("SCEP SDK original request differs");
                    } else value = coordinator.admit(new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.SCEP, endpoint.label(), requester,
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

    /**
     * Reports usable explicitly opted-in client-owned SDK enrollment.
     *
     * @param endpoint registered endpoint
     * @return whether opted-in active policy/runtime and a request-owned AltSignature profile are present
     * @throws NullPointerException if the endpoint is null
     * @throws RuntimeException if required realm/profile state cannot be resolved
     */
    public boolean hybridSdkAvailable(ScepEndpoint endpoint) {
        var policy = realm.enrollmentProfiles().find(endpoint.enrollmentProfileId());
        if (policy.isEmpty() || policy.orElseThrow().state() != zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE
                || policy.orElseThrow().sdkProfile().isEmpty() || realm.enrollmentCoordinator().isEmpty() || realm.enrollmentRuntime().isEmpty()
                || realm.session().semanticSigning().isEmpty()) return false;
        var profile = realm.session().profiles().requireActiveProfile(endpoint.profileId()).definition();
        return profile.hybridMode() instanceof zeroecho.pki.api.hybrid.HybridCertificateMode.AltSignature alt
                && alt.subjectKeySource() == zeroecho.pki.api.hybrid.HybridCertificateMode.AlternativeSubjectKeySource.REQUEST;
    }

    /**
     * Verifies/decrypts original CMS and checks native challenge policy without admitting enrollment.
     *
     * <p>The exact protected wire and decoded typed request are bound into the
     * retained SDK context. Challenge policy binds the endpoint commitment and
     * immutable response credential ID, without adding a password/secret digest
     * field. The original inner request itself may still contain confidential
     * challenge attributes and is not a public sanitized payload.</p>
     *
     * @param endpoint registered native endpoint
     * @param messageDer exact original protected PKIMessage
     * @param clientNonce exact client nonce
     * @param canonicalOrigin configured listener origin
     * @return retained immutable SDK challenge
     * @throws ScepProtocolException for malformed, unauthorized or unavailable native input
     * @throws IllegalArgumentException if the endpoint does not support the selected SCEP SDK profile
     */
    public zeroecho.pki.server.enrollment.EnrollmentSdkAdmission.Challenge challengeSdk(ScepEndpoint endpoint, byte[] messageDer,
            byte[] clientNonce, String canonicalOrigin) throws ScepProtocolException {
        try {
            if (!hybridSdkAvailable(endpoint)) throw new IllegalArgumentException("SCEP SDK profile unavailable");
            var verified = ScepCodec.verifyRequest(messageDer); var requester = sdkRequester(verified.requesterCertificate());
            String credential = runtime().activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.SCEP, endpoint.authorityId());
            try (var lease = runtime().acquire(credential)) {
                var request = ScepCodec.decryptRequest(verified, lease.responseChain().getFirst(), lease.privateKey());
                return realm.enrollmentCoordinator().orElseThrow().challengeSdk(sdkAdmission(endpoint, messageDer, request, requester, lease, canonicalOrigin), clientNonce);
            }
        } catch (ScepCodecException | IllegalArgumentException | zeroecho.pki.api.PkiException invalid) { throw new ScepProtocolException(400, "Invalid SCEP SDK request"); }
        catch (Exception unavailable) { throw new ScepProtocolException(503, "SCEP SDK enrollment unavailable"); }
    }

    /**
     * Admits dual proofs or reads the same consumed receipt with its retained native CMS owner/credential.
     *
     * <p>Both calls still verify/decrypt the exact protected CMS using the selected
     * credential. Consumed replay requires byte-identical original wire, owner,
     * endpoint/origin and retained credential/authority/issuer/path; it avoids a
     * fresh initial challenge-policy/admission attempt. OPEN acceptance checks
     * current native policy and exact retained SDK proofs through the coordinator.
     * No retry substitutes today's credential for an accepted receipt's selection.</p>
     *
     * @param endpoint registered endpoint
     * @param messageDer exact original CMS bytes
     * @param intentId retained SDK challenge
     * @param sdkRequestId stable acceptance identity
     * @param primaryProof primary client proof
     * @param alternativeProof alternative client proof
     * @param canonicalOrigin configured listener origin
     * @param cancellation transport cancellation
     * @return ordinary protected SCEP CertRep, including pending and terminal outcomes
     * @throws ScepProtocolException for invalid proof/owner/wire or unavailable custody
     * @throws IllegalArgumentException if the repeated SCEP wire bytes differ from the retained original or the
     *         authenticated SCEP SDK owner differs from the retained owner
     */
    public byte[] acceptSdk(ScepEndpoint endpoint, byte[] messageDer, String intentId, String sdkRequestId,
            byte[] primaryProof, byte[] alternativeProof, String canonicalOrigin, CancellationSignal cancellation) throws ScepProtocolException {
        try {
            var coordinator = realm.enrollmentCoordinator().orElseThrow(); var sdk = coordinator.retainedSdkIntent(intentId).orElseThrow();
            var original = sdk.admission(); var nativeAdmission = original.admission();
            if (nativeAdmission.protocol() != EnrollmentTransaction.Protocol.SCEP || !nativeAdmission.endpointId().equals(endpoint.label())
                    || !original.canonicalOrigin().equals(canonicalOrigin) || !Arrays.equals(sdk.nativeWire().orElseThrow(), messageDer)) throw new IllegalArgumentException("SCEP SDK retained wire differs");
            var verified = ScepCodec.verifyRequest(messageDer); var requester = sdkRequester(verified.requesterCertificate());
            if (!requester.actorId().equals(nativeAdmission.requester().actorId())
                    || !requester.certificate().equals(nativeAdmission.requester().certificate())) throw new IllegalArgumentException("SCEP SDK owner differs");
            Optional<EnrollmentTransaction> retained = sdk.enrollmentId().flatMap(coordinator::find);
            String credential = retained.map(value -> value.intent().source().credentialId().orElseThrow())
                    .orElseGet(() -> runtime().activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.SCEP, endpoint.authorityId()));
            try (var lease = runtime().acquire(credential)) {
                var ra = lease.responseChain().getFirst(); var key = lease.privateKey();
                var request = ScepCodec.decryptRequest(verified, ra, key); EnrollmentTransaction value;
                if (sdk.state() == zeroecho.pki.server.enrollment.EnrollmentSdkIntent.State.CONSUMED) {
                    var bound = retained.orElseThrow(); requireRetained(bound, requester, lease);
                    var read = new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.SCEP, nativeAdmission.endpointId(), requester,
                            nativeAdmission.transactionId(), nativeAdmission.operation(), nativeAdmission.payload(), nativeAdmission.validity(), nativeAdmission.predecessorId(), nativeAdmission.protocolDeadline());
                    var supplied = new zeroecho.pki.server.enrollment.EnrollmentSdkAdmission(read, original.expectedEndpointCommitment(), original.canonicalOrigin(), original.authenticationContext(), original.target(), Optional.empty(), Optional.of(messageDer));
                    value = coordinator.admitSdk(supplied, intentId, sdkRequestId, primaryProof, alternativeProof);
                } else {
                    value = coordinator.admitSdk(sdkAdmission(endpoint, messageDer, request, requester, lease, canonicalOrigin), intentId, sdkRequestId, primaryProof, alternativeProof);
                    requireRetained(value, requester, lease); value = coordinator.dispatch(value.id(), cancellation);
                }
                return sdkReply(request, value, ra, key);
            }
        } catch (ScepCodecException | IllegalArgumentException | zeroecho.pki.api.PkiException invalid) { throw new ScepProtocolException(400, "Invalid SCEP SDK request"); }
        catch (Exception unavailable) { throw new ScepProtocolException(503, "SCEP SDK enrollment unavailable"); }
    }

    private byte[] sdkReply(ScepPkiMessage request, EnrollmentTransaction value, X509Certificate ra, PrivateKey key) throws IOException, ScepCodecException {
        return switch (value.state()) {
            case ISSUED -> ScepCodec.buildCertRepSuccess(request.transactionId(), request.senderNonce(), issuedCertificate(value), request.requesterCert(), ra, key);
            case REJECTED, EXPIRED, FAILED -> failure(request, ra, key);
            default -> ScepCodec.buildCertRepPending(request.transactionId(), request.senderNonce(), ra, key);
        };
    }
    private EnrollmentTransaction.Requester sdkRequester(X509Certificate certificate) throws java.security.cert.CertificateEncodingException {
        var evidence = CertificateIdentityEvidence.fromCertificate(realm.configuration().realmId(), certificate);
        return new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.SCEP_SIGNER, evidence.certificateSha256(), IssuanceExecutionEvidence.Authentication.SCEP_CMS,
                Optional.of(evidence), Optional.of(evidence.canonicalKeySha256()), evidence.legacySpkiSha256(), new EnrollmentIdentityAliases.Snapshot(realm.configuration().realmId(), Set.of()));
    }
    private zeroecho.pki.server.enrollment.EnrollmentSdkAdmission sdkAdmission(ScepEndpoint endpoint, byte[] messageDer,
            ScepPkiMessage request, EnrollmentTransaction.Requester requester, EnrollmentRuntime.CredentialLease lease, String canonicalOrigin) throws ScepCodecException {
        if (!hybridSdkAvailable(endpoint) || request.messageType() != ScepCodec.MSG_PKCS_REQ
                || !challengeMatches(ScepCodec.extractChallengePassword(request.innerContent()), endpoint.challengePasswordHash())) throw new IllegalArgumentException("SCEP SDK initial policy rejected");
        var parsed = zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.parse(new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, request.innerContent()));
        var snapshot = endpoints.requireCurrent(endpoint); String credential = lease.configuration().credentialId();
        // Exact allocated policy transcript: full endpoint/challenge policy plus immutable response credential ID.
        var policyInputs = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(java.util.Map.of(
                "endpointCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(snapshot.commitment()),
                "credentialId", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(credential)));
        String transaction = digest(request.transactionId().getBytes(StandardCharsets.US_ASCII));
        var context = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(java.util.Map.ofEntries(
                java.util.Map.entry("endpointId", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(endpoint.label())), java.util.Map.entry("endpointCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(snapshot.commitment())),
                java.util.Map.entry("signerCertificateSha256", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(requester.certificate().orElseThrow().certificateSha256())),
                java.util.Map.entry("transactionIdSha256", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(transaction)), java.util.Map.entry("senderNonceSha256", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(digest(request.senderNonce()))),
                java.util.Map.entry("nativeMessageSha512", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text("sha512:" + HexFormat.of().formatHex(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(messageDer)))),
                java.util.Map.entry("challengePolicyCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text("sha256:" + digest(policyInputs.encode()))),
                java.util.Map.entry("challengeAuthenticated", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.bool(true)), java.util.Map.entry("messageType", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(Integer.toString(request.messageType()))),
                java.util.Map.entry("requestKind", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text("PKCS10"))));
        var auth = new zeroecho.pki.api.hybrid.sdk.HybridSdkFrame(6, java.util.Map.of(1, sdkText(requester.actorId()), 2, sdkText("scep-cms-v1"),
                3, zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(sdkText("sha256:" + requester.certificate().orElseThrow().certificateSha256())), 4, sdkText("scep-v1"), 5, context.encode()));
        var profiles = realm.enrollmentProfiles(); var policy = profiles.find(endpoint.enrollmentProfileId()).orElseThrow();
        var target = new zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget(1, "SCEP", endpoint.label(), snapshot.revision(), snapshot.commitment(), endpoint.enrollmentProfileId(), profiles.revision(endpoint.enrollmentProfileId()),
                zeroecho.pki.server.enrollment.EnrollmentProfileService.commitment(policy), "ISSUE", X509EnrollmentPayload.Kind.PKCS10, transaction,
                "sha512:" + HexFormat.of().formatHex(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(auth.encode())));
        var admission = new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.SCEP, endpoint.label(), requester, transaction, EnrollmentTransaction.Operation.ISSUE, parsed.originalPayload(), Optional.empty(), Optional.empty());
        return new zeroecho.pki.server.enrollment.EnrollmentSdkAdmission(admission, snapshot.commitment(), canonicalOrigin, auth, target, Optional.empty(), Optional.of(messageDer));
    }
    private static byte[] sdkText(String value) { return value.getBytes(StandardCharsets.UTF_8); }

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
