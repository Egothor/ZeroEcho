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
package zeroecho.pki.server.acme;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import java.util.Optional;
import java.util.Set;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.RevocationEvidenceExecutor;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.application.IssuanceExecutionEvidence;
import zeroecho.pki.server.ServerControlStore;

/**
 * Provides orders operations for the ACME service.
 */
final class AcmeOrdersOperations {
    private final AcmeService owner;
    /**
     * Creates an operation handler bound to the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmeOrdersOperations(AcmeService owner) { this.owner = owner; }

    /**
     * Creates an order and its authorizations under the selected directory policy.
     */
    /* default */ AcmeState.Order createOrder(String accountId, String expectedAccountCommitment,
            AcmeState.Directory directory,
            List<AcmeState.Identifier> requested, Optional<Instant> notBefore, Optional<Instant> notAfter,
            Duration orderLifetime){
        AcmeState.Account account = owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        owner.operations.policy.requireAccountDirectory(account, directory);
        owner.operations.policy.requireActiveAdmission(directory);
        List<AcmeState.Identifier> identifiers = owner.operations.shared.canonicalIdentifiers(requested, directory);
        Instant now = owner.clock.instant(); Instant expires = now.plus(orderLifetime);
        List<AcmeState.Authorization> authorizations = new ArrayList<>();
        List<AcmeState.Challenge> challenges = new ArrayList<>();
        for (AcmeState.Identifier identifier : identifiers) {
            AuthorizationGraph graph = authorizationGraph(identifier, directory, accountId, expires, now);
            authorizations.add(graph.authorization()); challenges.addAll(graph.challenges());
        }
        String orderId = owner.operations.shared.id("order");
        authorizations = authorizations.stream().map(value -> new AcmeState.Authorization(value.authorizationId(),
                orderId, value.accountId(), value.identifier(), value.status(), value.challengeIds(), value.expiresAt(),
                value.evidenceId(), AcmeService.ZERO)).toList();
        AcmeState.Order order = new AcmeState.Order(orderId, accountId, directory.directoryId(), directory.revision(),
                directory.policyCommitment(), directory.authorityId(), directory.profile(), directory.issuerId(),
                directory.issuancePathId(), directory.issuancePathCommitment(), identifiers, notBefore, notAfter,
                AcmeState.OrderStatus.PENDING, authorizations.stream().map(AcmeState.Authorization::authorizationId).toList(),
                Optional.empty(), Optional.empty(), Optional.empty(), now, expires, AcmeService.ZERO);
        AcmeState.Order created = owner.store.createOrderGraph(order, authorizations, challenges).order();
        owner.operations.shared.audit("ACME_ORDER_CREATED", accountId, Map.of("order", created.orderId(),
                "directory", created.directoryId()));
        return created;
    }

    /**
     * Counts pending orders for the account, stopping at the supplied limit.
     */
    /* default */ int pendingOrderCount(String accountId, int stopAt){
        if (stopAt <= 0) { throw new IllegalArgumentException("ACME pending-order bound is invalid"); }
        int offset = 0; int count = 0;
        while (true) {
            ServerControlStore.Page<AcmeState.Order> page = owner.store.page(AcmeState.Order.class, offset, 256);
            for (AcmeState.Order order : page.values()) {
                if (order.accountId().equals(accountId) && order.status() != AcmeState.OrderStatus.VALID
                        && order.status() != AcmeState.OrderStatus.INVALID && ++count >= stopAt) { return count; }
            }
            if (!page.hasMore()) { return count; }
            offset = page.nextOffset();
        }
    }

    /**
     * Revokes a certificate after checking the account, directory and certificate bindings.
     */
    /* default */ RevocationRecord revokeCertificate(String accountId, String expectedAccountCommitment,
            AcmeState.Directory directory, byte[] certificateDer, RevocationReason reason, String requestId){
        Objects.requireNonNull(certificateDer, "certificateDer"); Objects.requireNonNull(reason, "reason");
        AcmeState.Account account = owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        String digest = owner.operations.shared.digestBytes(certificateDer); AcmeState.Order owning = null; int offset = 0;
        while (owning == null) {
            ServerControlStore.Page<AcmeState.Order> page = owner.store.page(AcmeState.Order.class, offset, 256);
            for (AcmeState.Order order : page.values()) {
                if (order.accountId().equals(accountId) && order.directoryId().equals(directory.directoryId())
                        && order.status() == AcmeState.OrderStatus.VALID && order.credentialId().isPresent()) {
                    zeroecho.pki.api.credential.Credential credential = owner.realm.session().repository()
                            .credential(order.credentialId().orElseThrow()).orElseThrow();
                    if (credential.content().sha256().equals(digest)) { owning = order; break; }
                }
            }
            if (owning != null || !page.hasMore()) { break; }
            offset = page.nextOffset();
        }
        if (owning == null) { throw new SecurityException("ACME certificate is unavailable"); }
        PkiId credentialId = owning.credentialId().orElseThrow();
        owner.operations.shared.validatePublicationCorrelation(account, owning, directory, credentialId);
        PkiOperation.RevokeCredential operation = new PkiOperation.RevokeCredential(credentialId, reason);
        RevocationExecutionEvidence evidence = RevocationExecutionEvidence.acme(accountId,
                owner.realm.configuration().realmId().value(), requestId);
        PkiOperationOutcome outcome = RevocationEvidenceExecutor.require(owner.realm.session().operations())
                .executeRevocation(operation, evidence, CancellationSignal.NONE);
        if (!(outcome instanceof PkiOperationOutcome.Completed)) {
            throw new IllegalStateException("ACME revocation did not commit");
        }
        owner.operations.shared.signalReconciliation();
        RevocationRecord revoked = owner.realm.session().revocations().get(credentialId)
                .orElseThrow(() -> new IllegalStateException("Committed ACME revocation is unavailable"));
        owner.operations.shared.audit("ACME_CERTIFICATE_REVOKED", accountId, Map.of("order", owning.orderId()));
        return revoked;
    }

    /**
     * Finalizes an order using the supplied certification request.
     */
    /* default */ AcmeState.Order finalizeOrder(String accountId, String expectedAccountCommitment,
            String orderId, byte[] csrDer){
        return owner.finalizeOrder(accountId, expectedAccountCommitment, orderId, csrDer, CancellationSignal.NONE);
    }

    /**
     * Finalizes an order using the supplied certification request.
     */
    // Retains the established safe diagnostic or standalone monitor boundary.
    @SuppressWarnings({ "PMD.PreserveStackTrace" })
    /* default */ AcmeState.Order finalizeOrder(String accountId, String expectedAccountCommitment,
            String orderId, byte[] csrDer, CancellationSignal cancellation){
        Objects.requireNonNull(cancellation, "cancellation");
        byte[] frozenCsr = Objects.requireNonNull(csrDer, "csrDer").clone();
        AcmeState.Account account = owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Order order = owner.operations.shared.requireOrder(orderId);
        if (!order.accountId().equals(accountId)) { throw new IllegalArgumentException("ACME order unavailable"); }
        if (order.status() != AcmeState.OrderStatus.READY && order.status() != AcmeState.OrderStatus.PROCESSING
                && order.status() != AcmeState.OrderStatus.VALID) { throw new IllegalStateException("ACME order is not ready"); }
        AcmeState.Directory directory = owner.operations.shared.requireDirectory(order.directoryId());
        owner.operations.policy.validateFrozenOrder(order, directory);
        CertificationRequestService requests = owner.realm.session().requests().orElseThrow();
        ParsedCertificationRequest parsed = requests.parseX509(new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, frozenCsr));
        owner.operations.shared.requireExactIdentifiers(parsed, order.identifiers());
        try { cancellation.throwIfCancelled(); }
        catch (java.io.InterruptedIOException cancelled) { throw new PkiException("ACME finalization was cancelled"); }
        Optional<EnrollmentTransaction> existing = owner.operations.enrollment.enrollmentFor(order, directory);
        EnrollmentTransaction transaction;
        if (existing.isPresent()) {
            transaction = existing.orElseThrow();
            if (!transaction.intent().requestSha256().equals(owner.operations.shared.digestBytes(frozenCsr))) { throw new IllegalStateException("ACME finalized request differs"); }
        } else {
            if (order.issuanceCommitment().isPresent() || order.status() != AcmeState.OrderStatus.READY
                    || !order.expiresAt().isAfter(owner.clock.instant())) { throw new IllegalStateException("ACME enrollment reference is unavailable"); }
            owner.operations.policy.requireActiveAdmission(directory);
            zeroecho.pkix.PublicKeyIdentity key = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(account.publicKeySpki());
            EnrollmentTransaction.Requester requester = new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT,
                    account.accountId(), IssuanceExecutionEvidence.Authentication.ACME_ACCOUNT_JWS, Optional.empty(),
                    Optional.of(key.canonicalSha256()), key.equivalentSubjectPublicKeyInfoSha256(),
                    new EnrollmentIdentityAliases.Snapshot(owner.realm.configuration().realmId(), Set.of()));
            transaction = owner.operations.enrollment.enrollment().admit(new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.ACME, directory.directoryId(),
                    requester, owner.operations.shared.digest(order.orderId()), EnrollmentTransaction.Operation.ISSUE,
                    new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, frozenCsr), owner.operations.bindings.orderValidity(order), Optional.empty(), Optional.of(order.expiresAt())));
        }
        owner.operations.bindings.requireEnrollmentBinding(order, directory, transaction);
        return owner.operations.enrollment.continueEnrollment(order, directory, account, transaction, cancellation);
    }

    /**
     * Returns the authenticated account's order, reconciling enrollment state as needed.
     */
    /* default */ AcmeState.Order order(String accountId, String expectedAccountCommitment, String orderId){
        return owner.order(accountId, expectedAccountCommitment, orderId, CancellationSignal.NONE);
    }

    /**
     * Returns the authenticated account's order, reconciling enrollment state as needed.
     */
    /* default */ AcmeState.Order order(String accountId, String expectedAccountCommitment, String orderId,
            CancellationSignal cancellation){
        Objects.requireNonNull(cancellation, "cancellation");
        AcmeState.Account account = owner.operations.accounts.requireAuthenticatedAccount(accountId, expectedAccountCommitment);
        AcmeState.Order order = owner.operations.shared.requireOrder(orderId);
        if (!order.accountId().equals(accountId)) { throw new IllegalArgumentException("ACME order unavailable"); }
        if (order.status() != AcmeState.OrderStatus.READY && order.status() != AcmeState.OrderStatus.PROCESSING
                && order.status() != AcmeState.OrderStatus.VALID) { return order; }
        AcmeState.Directory directory = owner.operations.shared.requireDirectory(order.directoryId());
        Optional<EnrollmentTransaction> transaction = owner.operations.enrollment.enrollmentFor(order, directory);
        if (transaction.isEmpty()) {
            if (order.issuanceCommitment().isPresent()) { throw new IllegalStateException("ACME enrollment reference is unavailable"); }
            return order;
        }
        owner.operations.bindings.requireEnrollmentBinding(order, directory, transaction.orElseThrow());
        return owner.operations.enrollment.continueEnrollment(order, directory, account, transaction.orElseThrow(), cancellation);
    }

    /**
     * One identifier's exact authorization and ordered challenge graph.
     */
    private record AuthorizationGraph(AcmeState.Authorization authorization, List<AcmeState.Challenge> challenges) { }
    private AuthorizationGraph authorizationGraph(AcmeState.Identifier identifier, AcmeState.Directory directory,
            String accountId, Instant expires, Instant now) {

            List<AcmeState.Challenge> challenges = new ArrayList<>();
            String authorizationId = owner.operations.shared.id("authorization"); List<String> challengeIds = new ArrayList<>();
            for (AcmeState.ChallengeType type : directory.challengeTypes().stream().sorted().toList()) {
                if (identifier.wildcard() && type != AcmeState.ChallengeType.DNS_01) { continue; }
                String provider = owner.operations.policy.providerFor(directory, type); String challengeId = owner.operations.shared.id("challenge");
                challengeIds.add(challengeId);
                challenges.add(new AcmeState.Challenge(challengeId, authorizationId, type, owner.operations.shared.token(),
                        AcmeState.ChallengeStatus.PENDING, provider, 0, Optional.empty(), Optional.empty(), now, now, AcmeService.ZERO));
            }
            if (challengeIds.isEmpty()) { throw new IllegalArgumentException("No ACME challenge supports an identifier"); }
            return new AuthorizationGraph(new AcmeState.Authorization(authorizationId, "order-pending", accountId, identifier,
                    AcmeState.AuthorizationStatus.PENDING, challengeIds, expires, Optional.empty(), AcmeService.ZERO), challenges);
            }

}
