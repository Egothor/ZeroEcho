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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import javax.security.auth.x500.X500Principal;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatusResolver;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiRepositoryContent;
import zeroecho.pki.application.RevocationEvidenceExecutor;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.enrollment.CmpTransaction;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentEndpointRegistry;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentRuntime;
import zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.cmp.CmpProtectedMessage;
import zeroecho.pkix.cmp.CrmfRequest;

/**
 * Authenticated CMP enrollment, replacement, revocation and CA discovery.
 * Exact CRMF requests use the shared durable approval/signing coordinator.
 * Responses and nonce progression are persisted before delivery; pre-admission
 * authorization refusals have no durable transaction or domain side effect.
 * Thread-safe; cryptography and domain calls execute outside the control monitor.
 */
public final class CmpService { // NOPMD CyclomaticComplexity - Aggregate CMP protocol lifecycle complexity across durable transaction/nonce progression; individual methods remain checked.
    private static final int CERT_CONFIRMATION_TYPE = 24;
    private static final int CERTIFICATE_BYTES = 1_048_576;
    private final ServerRealmContext realm;
    private final EnrollmentEndpointRegistry endpoints;
    private final Clock clock;
    private final SecureRandom random;

    /**
     * Creates a protocol adapter with the system clock and secure nonce source.
     * @param realm lifecycle-owned realm and enrollment runtime
     */
    public CmpService(ServerRealmContext realm) { this(realm, Clock.systemUTC(), new SecureRandom()); }

    /**
     * Creates an adapter with explicit time and nonce capabilities.
     * @param realm lifecycle-owned realm
     * @param clock authoritative protocol clock
     * @param random thread-safe cryptographic nonce and salt source
     */
    public CmpService(ServerRealmContext realm, Clock clock, SecureRandom random) {
        this.realm = Objects.requireNonNull(realm, "realm");
        this.endpoints = Objects.requireNonNull(realm.enrollmentEndpoints(), "enrollmentEndpoints");
        this.clock = Objects.requireNonNull(clock, "clock"); this.random = Objects.requireNonNull(random, "random");
    }

    /**
     * Registers a fully bound endpoint.
     * @param endpoint mandatory policy and authority binding
     */
    public void register(CmpEndpoint endpoint) { endpoints.register(Objects.requireNonNull(endpoint, "endpoint")); }
    /**
     * Removes the durable binding.
     * @param label exact endpoint label
     * @return removed endpoint, if present
     */
    public Optional<CmpEndpoint> deregister(String label) {
        return endpoints.deregister(EnrollmentEndpointRegistry.Protocol.CMP, label).map(value -> (CmpEndpoint) value);
    }
    /**
     * Looks up an endpoint.
     * @param label exact endpoint label
     * @return current endpoint, if present
     */
    public Optional<CmpEndpoint> find(String label) {
        return endpoints.find(EnrollmentEndpointRegistry.Protocol.CMP, label).map(value -> (CmpEndpoint) value);
    }
    /** {@return immutable endpoints in deterministic registry order} */
    public List<CmpEndpoint> list() {
        return endpoints.list(EnrollmentEndpointRegistry.Protocol.CMP).stream().map(value -> (CmpEndpoint) value).toList();
    }

    /**
     * Processes one bounded protected request using the owned enrollment runtime.
     * @param endpoint exact route binding
     * @param pkiMessageDer canonical protected DER message
     * @return protected response, durably retained after transaction admission
     * @throws CmpProtocolException for malformed, unauthenticated or unavailable work
     */
    public byte[] processMessage(CmpEndpoint endpoint, byte[] pkiMessageDer) throws CmpProtocolException {
        return processMessage(endpoint, pkiMessageDer, CancellationSignal.NONE);
    }

    /**
     * Processes a request with cooperative cancellation. Claimed signing work is
     * reconciled by its original receipt rather than submitted again after timeout.
     * @param endpoint exact route binding
     * @param pkiMessageDer bounded protected DER request
     * @param cancellation owned HTTP deadline/cancellation signal
     * @return same-mode protected response
     * @throws CmpProtocolException for malformed, unauthenticated or unavailable work
     */
    public byte[] processMessage(CmpEndpoint endpoint, byte[] pkiMessageDer, CancellationSignal cancellation) throws CmpProtocolException {
        Objects.requireNonNull(endpoint, "endpoint"); Objects.requireNonNull(cancellation, "cancellation");
        CmpProtectedMessage request;
        try { request = CmpProtectedMessage.parse(pkiMessageDer); }
        catch (RuntimeException invalid) { throw new CmpProtocolException(400, "Invalid CMP message"); } // NOPMD AvoidCatchingGenericException, PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        try {
            cancellation.throwIfCancelled();
            EnrollmentCoordinator coordinator = coordinator(); // NOPMD CloseResource - Borrowed realm coordinator; the realm owns its shutdown.
            Optional<CmpTransaction> retained = coordinator.findCmp(endpoint.label(), hash(request.transactionId()));
            EnrollmentRuntime runtime = realm.enrollmentRuntime().orElseThrow();
            String credential = retained.map(value -> value.frozen().source().credentialId().orElseThrow())
                    .orElseGet(() -> runtime.activeCredentialId(EnrollmentRuntimeConfiguration.Protocol.CMP, endpoint.authorityId()));
            try (EnrollmentRuntime.CredentialLease lease = runtime.acquire(credential)) {
                List<byte[]> authorityChain = authorityChain(lease.configuration());
                boolean pbm = retained.map(value -> value.frozen().requester().type() == IssuanceExecutionEvidence.ActorType.CMP_PBM)
                        .orElse(endpoint.protectionPolicy() == CmpProtectionPolicy.SHARED_SECRET_MAC);
                X500Principal serverName = pbm ? Pkix.parseCertificate(authorityChain.getFirst()).getSubjectX500Principal()
                        : lease.responseChain().getFirst().getSubjectX500Principal();
                try (CmpAuthentication authentication = CmpAuthentication.verify(request, pbm, lease, realm.configuration().realmId(),
                        serverName, clock.instant(), cancellation)) {
                    String wireHash = hash(pkiMessageDer);
                    if (retained.isPresent()) {
                        CmpTransaction value = retained.orElseThrow();
                        requireRetained(value, authentication, lease);
                        if (value.response().filter(response -> response.requestSha256().equals(wireHash)).isPresent()) {
                            return coordinator.cmpResponse(value);
                        }
                    }
                    // messageTime is optional in the admitted grammar; when supplied, bound freshness
                    // using the already configured pending lifetime rather than a new timing knob.
                    if (staleMessage(request, runtime)) {
                        return transientRejection(authentication, lease, serverName, cancellation);
                    }
                    if (retained.isEmpty()) {
                        if (!initialRequestAllowed(request, pbm)) {
                            return transientRejection(authentication, lease, serverName, cancellation);
                        }
                        if (!authorizeInitial(endpoint, request, authentication, lease)) {
                            return transientRejection(authentication, lease, serverName, cancellation);
                        }
                        retained = Optional.of(reserve(endpoint, request, wireHash, authentication, lease, authorityChain));
                    }
                    CmpTransaction value = retained.orElseThrow();
                    if (!continuationMatches(value, request, wireHash)) {
                        return transientRejection(authentication, lease, serverName, cancellation);
                    }
                    try {
                        return continueTransaction(value, request, wireHash, authentication, lease, serverName, authorityChain, cancellation);
                    } catch (AuthorizationDenied denied) {
                        // A caller that lost current authorization may not advance retained state.
                        return transientRejection(authentication, lease, serverName, cancellation);
                    }
                }
            }
        } catch (IllegalArgumentException invalid) { throw new CmpProtocolException(400, "CMP authentication or request validation failed"); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
        catch (Exception unavailable) { throw new CmpProtocolException(503, "CMP processing is unavailable"); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    private boolean authorizeInitial(CmpEndpoint endpoint, CmpProtectedMessage request,
            CmpAuthentication authentication, EnrollmentRuntime.CredentialLease lease) throws IOException {
        try {
            requireFreshLocalStatus(authentication);
            if (request.bodyType() == 7 || request.bodyType() == 11) {
                authorizeTarget(endpoint.authorityId(), request, authentication, lease);
            }
            return true;
        } catch (IllegalArgumentException unauthorized) {
            return false;
        }
    }

    private boolean staleMessage(CmpProtectedMessage request, EnrollmentRuntime runtime) {
        return request.messageTime().filter(time -> time.isBefore(clock.instant().minus(runtime.configuration().budgets().pendingLifetime()))
                || time.isAfter(clock.instant().plus(runtime.configuration().budgets().pendingLifetime()))).isPresent();
    }

    private static boolean initialRequestAllowed(CmpProtectedMessage request, boolean pbm) {
        return request.bodyType() != 25 && request.bodyType() != CERT_CONFIRMATION_TYPE
                && request.recipientNonce().isEmpty() && !(pbm && (request.bodyType() == 7 || request.bodyType() == 11));
    }

    private static boolean continuationMatches(CmpTransaction value, CmpProtectedMessage request, String wireHash) {
        if (value.response().isEmpty()) {
            return value.frozen().originalWireSha256().equals(wireHash);
        }
        CmpTransaction.Response prior = value.response().orElseThrow();
        return !prior.terminal() && request.recipientNonce().isPresent()
                && MessageDigest.isEqual(request.recipientNonce().orElseThrow(), HexFormat.of().parseHex(prior.senderNonce()))
                && !Arrays.equals(request.senderNonce(), HexFormat.of().parseHex(prior.recipientNonce()))
                && request.requestId().equals(value.frozen().requestId());
    }

    private CmpTransaction reserve(CmpEndpoint endpoint, CmpProtectedMessage request, String wireHash, CmpAuthentication authentication,
            EnrollmentRuntime.CredentialLease lease, List<byte[]> authorityChain) throws java.security.cert.CertificateEncodingException {
        EnrollmentEndpointRegistry.Snapshot snapshot = endpoints.requireCurrent(endpoint);
        EnrollmentRuntimeConfiguration.CredentialSet credential = lease.configuration();
        CaRecord authority = realm.session().repository().authority(new PkiId(endpoint.authorityId())).orElseThrow();
        IssuerChainPath path = realm.session().repository().chainPath(new PkiId(credential.chainPathId())).orElseThrow();
        EnrollmentTransaction.Source source = new EnrollmentTransaction.Source(EnrollmentTransaction.Protocol.CMP, endpoint.label(), "CMP:" + endpoint.label(),
                snapshot.revision(), snapshot.commitment(), endpoint.enrollmentProfileId(),
                EnrollmentProfileService.commitment(realm.enrollmentProfiles().find(endpoint.enrollmentProfileId()).orElseThrow()),
                Optional.of(credential.credentialId()));
        Instant now = clock.instant();
        Instant expires = now.plus(realm.enrollmentRuntime().orElseThrow().configuration().budgets().pendingLifetime());
        Instant credentialDeadline = realm.enrollmentRuntime().orElseThrow().admissionDeadline(credential.credentialId());
        if (credentialDeadline.isBefore(expires)) {
            expires = credentialDeadline;
        }
        return coordinator().reserveCmp(new CmpTransaction.Frozen(realm.configuration().realmId(), source, authentication.requester(), authority.caId(),
                realm.session().profiles().requireActiveProfile(endpoint.profileId()).reference(), new PkiId(credential.issuerId()),
                path.pathId(), path.pathCommitment(), hash(request.transactionId()), wireHash, request.bodyType(), request.requestId(),
                request.certificationRequest().map(CmpService::hash), request.requestsImplicitConfirmation(), now, expires,
                responseBound(lease, authorityChain)));
    }

    private byte[] continueTransaction(CmpTransaction manifest, CmpProtectedMessage request, String wireHash, CmpAuthentication authentication,
            EnrollmentRuntime.CredentialLease lease, X500Principal serverName, List<byte[]> authorityChain, CancellationSignal cancellation) throws IOException {
        CmpProtectedMessage.Verified verified = authentication.verified();
        CmpTransaction.Confirmation confirmation = CmpTransaction.Confirmation.NONE;
        Optional<Instant> deadline = Optional.empty();
        if (manifest.frozen().enrollment()) {
            return continueEnrollment(manifest, request, wireHash, authentication, lease, serverName, cancellation);
        }
        CmpProtectedMessage.Response response;
        if (request.bodyType() == 11 && manifest.frozen().originalType() == 11) {
            return continueRevocation(manifest, request, wireHash, authentication, lease, serverName, cancellation);
        } else if (request.bodyType() == 21 && manifest.frozen().originalType() == 21) {
            if (!clock.instant().isBefore(manifest.frozen().expiresAt())) {
                return retainRejection(manifest, request, wireHash, authentication, lease, serverName, cancellation);
            }
            coordinator().requireCmpCurrentSource(manifest);
            requireFreshLocalStatus(authentication); response = verified.caCertificates(authorityChain);
        } else {
            return transientRejection(authentication, lease, serverName, cancellation);
        }
        return retainResponse(manifest, request, wireHash, authentication, lease, serverName, cancellation,
                new ResponsePlan(response, deadline, confirmation, true));
    }

    private byte[] continueRevocation(CmpTransaction manifest, CmpProtectedMessage request, String wireHash,
            CmpAuthentication authentication, EnrollmentRuntime.CredentialLease lease, X500Principal serverName,
            CancellationSignal cancellation) throws IOException {
        Credential target = authorizeTarget(manifest.frozen().authorityId().value(), request, authentication, lease);
        RevocationExecutionEvidence.Authorization grant = holder(target, authentication)
                ? RevocationExecutionEvidence.Authorization.CMP_CERTIFICATE_HOLDER : RevocationExecutionEvidence.Authorization.CMP_AUTHORIZED_RA;
        RevocationExecutionEvidence evidence = RevocationExecutionEvidence.cmp(authentication.requester().actorId(),
                realm.configuration().realmId().value(), manifest.id(), grant, manifest.frozen().originalWireSha256());
        boolean alreadyCommitted = realm.session().revocations().get(target.credentialId()).filter(value ->
                value.transition().state() == RevocationState.PERMANENTLY_REVOKED
                        && RevocationExecutionEvidence.decode(value.transition().attributes()).filter(evidence::equals).isPresent()).isPresent();
        if (!alreadyCommitted) {
            if (!clock.instant().isBefore(manifest.frozen().expiresAt())) {
                return retainRejection(manifest, request, wireHash, authentication, lease, serverName, cancellation);
            }
            coordinator().requireCmpCurrentSource(manifest);
            requireFreshLocalStatus(authentication);
            PkiOperationOutcome outcome = RevocationEvidenceExecutor.require(realm.session().operations()).executeRevocation(
                    new PkiOperation.RevokeCredential(target.credentialId(), reason(request.revocationReason())), evidence, cancellation);
            if (!(outcome instanceof PkiOperationOutcome.Completed)) {
                throw unavailable();
            }
        }
        return retainResponse(manifest, request, wireHash, authentication, lease, serverName, cancellation,
                new ResponsePlan(authentication.verified().revoked(), Optional.empty(), CmpTransaction.Confirmation.NONE, true));
    }

    private byte[] continueEnrollment(CmpTransaction manifest, CmpProtectedMessage request, String wireHash,
            CmpAuthentication authentication, EnrollmentRuntime.CredentialLease lease, X500Principal serverName,
            CancellationSignal cancellation) throws IOException {
        CmpTransaction current = manifest;
        CmpProtectedMessage.Verified verified = authentication.verified();
        EnrollmentTransaction enrollment;
        if (current.enrollmentId().isEmpty()) {
            if (request.bodyType() != current.frozen().originalType()) {
                return transientRejection(authentication, lease, serverName, cancellation);
            }
            if (!clock.instant().isBefore(current.frozen().expiresAt())) {
                return retainRejection(current, request, wireHash, authentication, lease, serverName, cancellation);
            }
            requireFreshLocalStatus(authentication);
            Optional<PkiId> predecessor = request.bodyType() == 7 ? Optional.of(authorizeTarget(current.frozen().authorityId().value(),
                    request, authentication, lease).credentialId()) : Optional.empty();
            enrollment = coordinator().admitCmp(new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.CMP,
                    current.frozen().source().label(), current.frozen().requester(), current.frozen().transactionSha256(),
                    request.bodyType() == 7 ? EnrollmentTransaction.Operation.REPLACE : EnrollmentTransaction.Operation.ISSUE,
                    new X509EnrollmentPayload(X509EnrollmentPayload.Kind.CRMF, request.certificationRequest().orElseThrow()),
                    Optional.empty(), predecessor), current);
            current = coordinator().findCmp(current.frozen().source().label(), current.frozen().transactionSha256()).orElseThrow();
        } else {
            enrollment = coordinator().find(current.enrollmentId().orElseThrow()).orElseThrow();
        }
        if (request.bodyType() == CERT_CONFIRMATION_TYPE) {
            return continueConfirmation(current, enrollment, request, wireHash, authentication, lease, serverName, cancellation);
        }
        if (request.bodyType() != 25 && (current.response().isPresent() || request.bodyType() != current.frozen().originalType())) {
            return transientRejection(authentication, lease, serverName, cancellation);
        }
        enrollment = coordinator().dispatch(enrollment.id(), cancellation, () -> requireFreshLocalStatus(authentication));
        return retainResponse(current, request, wireHash, authentication, lease, serverName, cancellation,
                issuanceResponse(current, request, enrollment, verified));
    }

    private byte[] continueConfirmation(CmpTransaction manifest, EnrollmentTransaction enrollment,
            CmpProtectedMessage request, String wireHash, CmpAuthentication authentication,
            EnrollmentRuntime.CredentialLease lease, X500Principal serverName, CancellationSignal cancellation) throws IOException {
        CmpProtectedMessage.Verified verified = authentication.verified();
        CmpTransaction.Response previous = manifest.response().orElseThrow();
        if (previous.confirmation() != CmpTransaction.Confirmation.AWAITING || enrollment.state() != EnrollmentTransaction.State.ISSUED) {
            return transientRejection(authentication, lease, serverName, cancellation);
        }
        CmpProtectedMessage.Response response;
        CmpTransaction.Confirmation confirmation;
        if (clock.instant().isBefore(previous.confirmationDeadline().orElseThrow())) {
            if (!confirmationMatches(request, certificate(enrollment.credentialId().orElseThrow()))) {
                return transientRejection(authentication, lease, serverName, cancellation);
            }
            response = verified.confirmed();
            confirmation = request.confirmationAccepted() ? CmpTransaction.Confirmation.ACCEPTED : CmpTransaction.Confirmation.REJECTED;
        } else {
            response = verified.rejected(); confirmation = CmpTransaction.Confirmation.EXPIRED;
        }
        return retainResponse(manifest, request, wireHash, authentication, lease, serverName, cancellation,
                new ResponsePlan(response, Optional.empty(), confirmation, true));
    }

    private ResponsePlan issuanceResponse(CmpTransaction manifest, CmpProtectedMessage request,
            EnrollmentTransaction enrollment, CmpProtectedMessage.Verified verified) throws IOException {
        CmpProtectedMessage.Response response;
        CmpTransaction.Confirmation confirmation = CmpTransaction.Confirmation.NONE;
        Optional<Instant> deadline = Optional.empty();
        boolean terminal = false;
        switch (enrollment.state()) {
            case ISSUED -> {
                boolean implicit = manifest.frozen().implicitConfirmation();
                Instant until = manifest.response().flatMap(CmpTransaction.Response::confirmationDeadline)
                        .orElse(clock.instant().plus(realm.enrollmentRuntime().orElseThrow().configuration().budgets().pendingLifetime()));
                if (implicit || clock.instant().isBefore(until)) {
                    response = verified.certificate(manifest.frozen().originalType(), certificate(enrollment.credentialId().orElseThrow()), implicit, until);
                    confirmation = implicit ? CmpTransaction.Confirmation.ACCEPTED : CmpTransaction.Confirmation.AWAITING;
                    deadline = implicit ? Optional.empty() : Optional.of(until); terminal = implicit;
                } else {
                    response = verified.rejected(); confirmation = CmpTransaction.Confirmation.EXPIRED; terminal = true;
                }
            }
            case REJECTED, EXPIRED, FAILED -> { response = verified.rejected(); terminal = true; }
            default -> response = request.bodyType() == 25
                    ? verified.poll(Math.toIntExact(realm.enrollmentRuntime().orElseThrow().configuration().budgets().retryAfter().getSeconds())) : verified.waiting();
        }
        return new ResponsePlan(response, deadline, confirmation, terminal);
    }

    private record ResponsePlan(CmpProtectedMessage.Response response, Optional<Instant> deadline,
            CmpTransaction.Confirmation confirmation, boolean terminal) { }

    private byte[] retainResponse(CmpTransaction manifest, CmpProtectedMessage request, String wireHash,
            CmpAuthentication authentication, EnrollmentRuntime.CredentialLease lease, X500Principal serverName,
            CancellationSignal cancellation, ResponsePlan plan) {
        byte[] nonce = nonce();
        byte[] bytes = protect(authentication, plan.response(), lease, serverName, nonce, cancellation);
        CmpTransaction.Response metadata = new CmpTransaction.Response(wireHash, hash(bytes), bytes.length, HexFormat.of().formatHex(nonce),
                HexFormat.of().formatHex(request.senderNonce()), plan.deadline(), plan.confirmation(), plan.terminal());
        coordinator().storeCmpResponse(manifest, bytes, metadata);
        return bytes;
    }

    private Credential authorizeTarget(String authority, CmpProtectedMessage request, CmpAuthentication authentication,
            EnrollmentRuntime.CredentialLease lease) throws IOException {
        if (authentication.certificate().isEmpty()) {
            throw new AuthorizationDenied();
        }
        CrmfRequest.CertificateReference reference = request.bodyType() == 7
                ? CrmfRequest.parse(request.certificationRequest().orElseThrow()).oldCertificate().orElseThrow()
                : request.revokedCertificate().orElseThrow();
        Credential credential = realm.session().repository().credential(new PkiId(lease.configuration().issuerId()), reference.serialNumber())
                .orElseThrow(CmpService::unavailable);
        byte[] der = certificate(credential.credentialId());
        X509Certificate exact = Pkix.parseCertificate(der);
        if (!credential.issuerRef().caId().value().equals(authority) || !reference.issuer().equals(exact.getIssuerX500Principal())
                || !reference.serialNumber().equals(exact.getSerialNumber()) || !hash(der).equals(credential.content().sha256())
                || !credential.credentialId().value().equals("x509:" + hash(der))
                || !holder(credential, authentication)
                    && !lease.configuration().authorizedRaKeys().contains(authentication.requester().canonicalKeySha256().orElseThrow())) {
            throw new AuthorizationDenied();
        }
        return credential;
    }

    private static boolean holder(Credential credential, CmpAuthentication authentication) {
        return authentication.requester().certificate().filter(value -> value.certificateSha256().equals(credential.content().sha256())).isPresent();
    }

    private static boolean confirmationMatches(CmpProtectedMessage request, byte[] certificate) {
        try {
            return MessageDigest.isEqual(request.confirmationHash().orElseThrow(),
                    CmpProtectedMessage.certificateConfirmationHash(certificate, request.confirmationHashAlgorithm()));
        } catch (IllegalArgumentException invalid) { return false; }
    }

    private void requireFreshLocalStatus(CmpAuthentication authentication) {
        try {
        EffectiveCredentialStatusResolver.Evaluation evaluation = realm.session().credentialStatuses().beginEvaluation();
        for (X509Certificate certificate : authentication.trustedChain()) {
            requireLocalCertificateStatus(certificate, evaluation);
        }
        } catch (IOException | java.security.cert.CertificateEncodingException failure) { throw unavailable(); } // NOPMD PreserveStackTrace - This trust boundary exposes a fixed failure without provider, key, request or persisted-payload diagnostics.
    }

    private void requireLocalCertificateStatus(X509Certificate certificate, EffectiveCredentialStatusResolver.Evaluation evaluation)
            throws IOException, java.security.cert.CertificateEncodingException {
        byte[] der = certificate.getEncoded(); String digest = hash(der);
        Optional<Credential> known = realm.session().repository().credential(new PkiId("x509:" + digest));
        if (known.isPresent()) {
            Credential exact = known.orElseThrow();
            if (!exact.content().sha256().equals(digest) || !Arrays.equals(der, certificate(exact.credentialId()))
                    || evaluation.resolve(exact) != EffectiveCredentialStatus.USABLE) {
                throw new AuthorizationDenied();
            }
        }
    }

    private byte[] retainRejection(CmpTransaction manifest, CmpProtectedMessage request, String wireHash,
            CmpAuthentication authentication, EnrollmentRuntime.CredentialLease lease, X500Principal serverName,
            CancellationSignal cancellation) {
        byte[] nonce = nonce();
        byte[] bytes = protect(authentication, authentication.verified().rejected(), lease, serverName, nonce, cancellation);
        coordinator().storeCmpResponse(manifest, bytes, new CmpTransaction.Response(wireHash, hash(bytes), bytes.length,
                HexFormat.of().formatHex(nonce), HexFormat.of().formatHex(request.senderNonce()), Optional.empty(),
                CmpTransaction.Confirmation.NONE, true));
        return bytes;
    }

    private static void requireRetained(CmpTransaction manifest, CmpAuthentication authentication, EnrollmentRuntime.CredentialLease lease) {
        EnrollmentTransaction.Requester expected = manifest.frozen().requester();
        EnrollmentTransaction.Requester actual = authentication.requester();
        EnrollmentRuntimeConfiguration.CredentialSet credential = lease.configuration();
        if (expected.type() != actual.type() || !expected.actorId().equals(actual.actorId()) || expected.authentication() != actual.authentication()
                || !expected.certificate().equals(actual.certificate()) || !expected.canonicalKeySha256().equals(actual.canonicalKeySha256())
                || !manifest.frozen().source().credentialId().equals(Optional.of(credential.credentialId()))
                || !manifest.frozen().authorityId().value().equals(credential.authorityId())
                || !manifest.frozen().issuerId().value().equals(credential.issuerId())
                || !manifest.frozen().pathId().value().equals(credential.chainPathId())) {
            throw new IllegalArgumentException("CMP retained identity is unavailable");
        }
    }

    private byte[] transientRejection(CmpAuthentication authentication, EnrollmentRuntime.CredentialLease lease,
            X500Principal serverName, CancellationSignal cancellation) {
        return protect(authentication, authentication.verified().rejected(), lease, serverName, nonce(), cancellation);
    }
    private byte[] protect(CmpAuthentication authentication, CmpProtectedMessage.Response response, EnrollmentRuntime.CredentialLease lease,
            X500Principal serverName, byte[] nonce, CancellationSignal cancellation) {
        byte[] salt = new byte[authentication.verified().request().isPbm() ? authentication.pbmPolicy().minimumSaltBytes() : 0];
        random.nextBytes(salt);
        return authentication.protect(response, lease, serverName, salt, nonce, clock.instant(), cancellation);
    }
    private byte[] nonce() { byte[] bytes = new byte[16]; random.nextBytes(bytes); return bytes; }

    private List<byte[]> authorityChain(EnrollmentRuntimeConfiguration.CredentialSet credential) throws IOException {
        IssuerChainPath path = realm.session().repository().chainPath(new PkiId(credential.chainPathId())).orElseThrow();
        if (!path.authorityId().value().equals(credential.authorityId()) || !path.issuerId().value().equals(credential.issuerId())
                || path.orderedCredentialIds().size() > 32) {
            throw unavailable();
        }
        List<byte[]> result = new ArrayList<>();
        for (PkiId id : path.orderedCredentialIds()) {
            result.add(certificate(id));
        }
        if (result.isEmpty()) {
            throw unavailable();
        }
        return List.copyOf(result);
    }
    private byte[] certificate(PkiId id) throws IOException {
        try (PkiRepositoryContent content = realm.session().repository().openCredential(id); InputStream input = content.openStream()) {
            byte[] der = input.readNBytes(CERTIFICATE_BYTES + 1);
            if (der.length == 0 || der.length > CERTIFICATE_BYTES) {
                throw unavailable();
            }
            return der;
        }
    }
    private static int responseBound(EnrollmentRuntime.CredentialLease lease, List<byte[]> authorityChain) throws java.security.cert.CertificateEncodingException {
        // One maximum leaf, exact genp CA sequence, exact signature extraCerts, plus
        // 64 KiB for bounded names, IDs, nonces, parameters, signature and DER framing.
        int bound = CERTIFICATE_BYTES + 65_536;
        for (byte[] certificate : authorityChain) {
            bound = Math.addExact(bound, certificate.length);
        }
        for (X509Certificate certificate : lease.responseChain()) {
            bound = Math.addExact(bound, certificate.getEncoded().length);
        }
        return bound;
    }
    private static RevocationReason reason(int value) {
        return switch (value) {
            case 0 -> RevocationReason.UNSPECIFIED; case 1 -> RevocationReason.KEY_COMPROMISE;
            case 2 -> RevocationReason.CA_COMPROMISE; case 3 -> RevocationReason.AFFILIATION_CHANGED;
            case 4 -> RevocationReason.SUPERSEDED; case 5 -> RevocationReason.CESSATION_OF_OPERATION;
            case 9 -> RevocationReason.PRIVILEGE_WITHDRAWN; case 10 -> RevocationReason.AA_COMPROMISE;
            default -> throw new IllegalArgumentException("Unsupported CMP revocation reason");
        };
    }
    private EnrollmentCoordinator coordinator() { return realm.enrollmentCoordinator().orElseThrow(); }
    private static String hash(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable", impossible); }
    }
    private static IllegalStateException unavailable() { return new IllegalStateException("CMP continuation is unavailable"); }
    /** Distinguishes authorization rejection from malformed CMP request syntax. */
    private static final class AuthorizationDenied extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        /* default */ AuthorizationDenied() { super("CMP authorization denied"); }
    }
}
