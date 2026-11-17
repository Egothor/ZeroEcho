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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HexFormat;
import zeroecho.pki.server.enrollment.EnrollmentCoordinator;
import zeroecho.pki.server.enrollment.EnrollmentProfileService;
import zeroecho.pki.server.enrollment.EnrollmentTransaction;
import zeroecho.pki.server.enrollment.EnrollmentIdentityAliases;
import zeroecho.pki.api.request.X509EnrollmentPayload;
import java.util.Optional;
import java.util.Set;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.issuance.RetainedIssuanceBinding;
import zeroecho.pki.application.IssuanceExecutionEvidence;

/**
 * Validates frozen enrollment bindings without changing the facade's selected actor or monitor.
 */
final class AcmeEnrollmentBindings {
    private final AcmeService owner;
    /**
     * Creates a binding validator for the supplied ACME service.
     *
     * @param owner service whose state and collaborators are used by this handler
     */
    /* default */ AcmeEnrollmentBindings(AcmeService owner) { this.owner = owner; }
    /**
     * Builds the enrollment requester identity from the retained ACME account key.
     */
    /* default */ EnrollmentTransaction.Requester sdkRequester(AcmeState.Account account){
        zeroecho.pkix.PublicKeyIdentity key = zeroecho.pkix.PublicKeyIdentity.fromSubjectPublicKeyInfo(account.publicKeySpki());
        return new EnrollmentTransaction.Requester(IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT, account.accountId(),
                IssuanceExecutionEvidence.Authentication.ACME_ACCOUNT_JWS, Optional.empty(), Optional.of(key.canonicalSha256()),
                key.equivalentSubjectPublicKeyInfoSha256(), new EnrollmentIdentityAliases.Snapshot(owner.realm.configuration().realmId(), Set.of()));
    }

    /**
     * Builds SDK admission evidence after validating the order, authorizations and requested
     * identifiers.
     */
    /* default */ zeroecho.pki.server.enrollment.EnrollmentSdkAdmission sdkAdmission(AcmeState.Account account, AcmeState.Order order,
            byte[] csrDer, String canonicalOrigin){
        AcmeState.Directory directory = owner.operations.shared.requireDirectory(order.directoryId());
        if (!owner.hybridSdkAvailable(directory) || order.status() != AcmeState.OrderStatus.READY || !owner.clock.instant().isBefore(order.expiresAt())) {
            throw new IllegalStateException("ACME SDK order is not ready");
        }
        owner.operations.policy.validateFrozenOrder(order, directory); owner.operations.policy.requireActiveAdmission(directory);
        zeroecho.pki.api.hybrid.sdk.ParsedHybridSdkRequest parsed = zeroecho.pki.api.hybrid.sdk.HybridSdkProofs.parse(new X509EnrollmentPayload(X509EnrollmentPayload.Kind.PKCS10, csrDer));
        owner.operations.shared.requireExactIdentifiers(parsed.primary(), order.identifiers());
        List<zeroecho.pki.api.hybrid.sdk.HybridSdkValue> authorizations = new ArrayList<>();
        for (String id : order.authorizationIds().stream().sorted().toList()) {
            AcmeState.Authorization authorization = owner.operations.shared.requireAuthorization(id);
            if (!authorization.accountId().equals(account.accountId()) || !authorization.orderId().equals(order.orderId())
                    || authorization.status() != AcmeState.AuthorizationStatus.VALID || !owner.clock.instant().isBefore(authorization.expiresAt())) {
                throw new IllegalStateException("ACME SDK authorization unavailable");
            }
            authorizations.add(zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(Map.of(
                    "authorizationId", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(authorization.authorizationId()),
                    "recordCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(authorization.commitment()))));
        }
        EnrollmentTransaction.Requester requester = owner.operations.bindings.sdkRequester(account); String keyHash = requester.canonicalKeySha256().orElseThrow();
        zeroecho.pki.api.hybrid.sdk.HybridSdkValue values = zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(Map.ofEntries(
                Map.entry("endpointId", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(directory.alias())), Map.entry("endpointCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(directory.commitment())),
                Map.entry("accountId", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(account.accountId())), Map.entry("accountKeySha256", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(keyHash)),
                Map.entry("orderId", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(order.orderId())), Map.entry("orderCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(order.commitment())),
                Map.entry("authorizationCommitment", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text("sha256:" + owner.operations.shared.digestBytes(zeroecho.pki.api.hybrid.sdk.HybridSdkValue.list(authorizations).encode()))),
                Map.entry("identifiers", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.list(order.identifiers().stream().map(value -> zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(Map.of(
                        "type", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text("dns"), "value", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text(value.value()), "wildcard", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.bool(value.wildcard())))).toList())),
                Map.entry("requestKind", zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text("PKCS10"))));
        zeroecho.pki.api.hybrid.sdk.HybridSdkFrame auth = new zeroecho.pki.api.hybrid.sdk.HybridSdkFrame(6, Map.of(1, owner.operations.bindings.sdkText(account.accountId()), 2, owner.operations.bindings.sdkText("acme-account-jws-v1"),
                3, zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(owner.operations.bindings.sdkText("sha256:" + keyHash)), 4, owner.operations.bindings.sdkText("acme-v1"), 5, values.encode()));
        zeroecho.pki.server.enrollment.EnrollmentProfile policy = owner.realm.enrollmentProfiles().find(directory.enrollmentProfileId()).orElseThrow();
        zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget target = new zeroecho.pki.api.hybrid.sdk.SdkEnrollmentTarget(1, "ACME", directory.alias(), directory.revision(), directory.commitment(),
                directory.enrollmentProfileId(), owner.realm.enrollmentProfiles().revision(directory.enrollmentProfileId()), EnrollmentProfileService.commitment(policy), "ISSUE", X509EnrollmentPayload.Kind.PKCS10,
                owner.operations.shared.digest(order.orderId()), "sha512:" + HexFormat.of().formatHex(zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.hash(auth.encode())));
        EnrollmentCoordinator.Admission admission = new EnrollmentCoordinator.Admission(EnrollmentTransaction.Protocol.ACME, directory.directoryId(), requester, owner.operations.shared.digest(order.orderId()),
                EnrollmentTransaction.Operation.ISSUE, parsed.originalPayload(), owner.operations.bindings.orderValidity(order), Optional.empty(), Optional.of(order.expiresAt()));
        return new zeroecho.pki.server.enrollment.EnrollmentSdkAdmission(admission, directory.commitment(), canonicalOrigin, auth, target, Optional.empty());
    }

    /**
     * Encodes text as UTF-8 for an SDK transcript.
     */
    /* default */ byte[] sdkText(String text){ return text.getBytes(StandardCharsets.UTF_8); }

    /**
     * Returns the explicitly requested validity interval, if present.
     */
    /* default */ Optional<Validity> orderValidity(AcmeState.Order order){
        return order.notBefore().map(start -> new Validity(start, order.notAfter().orElseThrow()));
    }

    /**
     * Checks that the retained enrollment transaction matches the frozen ACME order and
     * directory.
     */
    /* default */ void requireEnrollmentBinding(AcmeState.Order order, AcmeState.Directory directory, EnrollmentTransaction transaction){
        owner.operations.policy.validateFrozenOrder(order, directory);
        EnrollmentTransaction.Intent intent = transaction.intent();
        EnrollmentTransaction.Source source = intent.source();
        requireEnrollmentSource(order, directory, intent, source);
        requireEnrollmentSelection(order, intent, transaction);

        owner.operations.shared.requireExactIdentifiers(owner.operations.enrollment.enrollment().inspectIdentity(transaction.id()), order.identifiers());
        RetainedIssuanceBinding binding = owner.operations.enrollment.enrollment().issuanceBinding(transaction.id());
        if (order.issuanceCommitment().filter(value -> !value.equals(binding.effectiveCommitment())).isPresent()
                || order.signingOperationId().isPresent() && transaction.receipt().isPresent()
                        && !order.signingOperationId().orElseThrow().equals(transaction.receipt().orElseThrow().operationId())
                || order.credentialId().isPresent() && !order.credentialId().equals(transaction.credentialId())) {
            throw new IllegalStateException("ACME signing attachment differs");
        }
    }

    /**
     * Returns the validity retained by the SDK admission or the enrollment intent.
     */
    /* default */ Optional<Validity> requestedValidity(EnrollmentTransaction transaction){
        return transaction.intent().sdkProof().map(proof -> owner.operations.enrollment.enrollment().retainedSdkIntent(proof.intentId()).orElseThrow().admission().admission().validity())
                .orElse(transaction.intent().validity());
    }

    /**
     * Returns the directory commitment corresponding to its active admission state.
     */
    /* default */ String admittedDirectoryCommitment(AcmeState.Directory directory){
        // Admission only accepts ACTIVE directories. Later administrative suspension
        // must not invalidate already admitted work or certificate publication.
        return directory.status() == AcmeState.DirectoryStatus.ACTIVE ? directory.commitment()
                : ((AcmeState.Directory) new AcmeStateCodec().seal(owner.operations.shared.copyDirectory(directory, AcmeState.DirectoryStatus.ACTIVE))).commitment();
    }

    private void requireEnrollmentSource(AcmeState.Order order, AcmeState.Directory directory,
            EnrollmentTransaction.Intent intent, EnrollmentTransaction.Source source) {
        if (!intent.realmId().equals(owner.realm.configuration().realmId()) || source.protocol() != EnrollmentTransaction.Protocol.ACME
                || !source.label().equals(directory.alias()) || !source.recordId().equals(order.directoryId())
                || source.revision() != order.directoryRevision() || !source.commitment().equals(owner.operations.bindings.admittedDirectoryCommitment(directory))
                || !source.enrollmentProfileId().equals(directory.enrollmentProfileId())
                || intent.operation() != EnrollmentTransaction.Operation.ISSUE || !intent.transactionId().equals(owner.operations.shared.digest(order.orderId()))
                ) { throw new IllegalStateException("ACME frozen enrollment binding differs"); }
    }
    private void requireEnrollmentSelection(AcmeState.Order order, EnrollmentTransaction.Intent intent, EnrollmentTransaction transaction) {
        if (intent.requester().type() != IssuanceExecutionEvidence.ActorType.ACME_ACCOUNT || !intent.requester().actorId().equals(order.accountId())
                || !intent.authorityId().equals(order.authorityId()) || !intent.profile().equals(order.profile())
                || !intent.issuerId().equals(order.issuerId()) || !intent.pathId().equals(order.issuancePathId())
                || !intent.pathCommitment().equals(order.issuancePathCommitment()) || !owner.operations.bindings.requestedValidity(transaction).equals(owner.operations.bindings.orderValidity(order))
                || intent.requestKind() != X509EnrollmentPayload.Kind.PKCS10 || intent.expiresAt().isAfter(order.expiresAt())) { throw new IllegalStateException("ACME frozen enrollment binding differs"); }
    }

}
