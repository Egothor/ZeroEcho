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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.audit.AuditEvent;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofSubmission;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiResourceScopeResolver;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.application.RevocationEvidenceExecutor;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.acme.AcmeState;
import zeroecho.pki.spi.audit.AuditSink;

/** Gateway descriptor, multi-authority and approval enforcement coverage. */
class ServerOperationGatewayTest {
    @TempDir Path temporaryDirectory;

    @Test
    void authoritativeScopeResolutionPreservesCredentialEvidenceIntoTypedControlActor() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("requester"));
            opened.store().createPrincipal(ServerTestSupport.principal("reader"));
            Permission.Scope scope = new Permission.Scope(ServerTestSupport.REALM, Optional.of(ServerTestSupport.AUTHORITY),
                    Optional.empty(), Optional.of("profile-a"));
            opened.store().createGrant(ServerTestSupport.grant("read-approval", "reader", Permission.Effect.ALLOW,
                    Permission.Action.REQUEST_READ_ANY, Permission.ResourceType.APPROVAL, scope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            approvals.request("identity-approval", "test.operation", ServerTestSupport.DIGEST, scope, "requester",
                    new ApprovalService.Policy("identity-policy", 1, Set.of("reader"), Set.of(), true, Duration.ofHours(1), true));
            CertificateIdentityEvidence evidence = new CertificateIdentityEvidence(ServerTestSupport.REALM,
                    "1".repeat(64), "2".repeat(64), Set.of("3".repeat(64)), "4".repeat(64));
            AtomicReference<AdministrativeDecisionActor> observed = new AtomicReference<>();
            AtomicReference<Permission.Resource> authorized = new AtomicReference<>();
            {
                org.mockito.MockedConstruction<ServerControlOperationExecutor> construction = org.mockito.Mockito.mockConstruction(
                    ServerControlOperationExecutor.class, (executor, context) -> {
                    when(executor.protocolAvailable(any())).thenReturn(true);
                    org.mockito.Mockito.doAnswer(invocation -> {
                    observed.set(invocation.getArgument(1));
                    authorized.set(invocation.getArgument(2));
                    return new ServerControlOperationOutcome.Ordinary(new PkiOperationOutcome.Completed(
                    new PkiOperationResult(ServerControlOperation.InspectApproval.NAME, Map.of())));
                    }).when(executor).executeAuthorized(any(), any(AdministrativeDecisionActor.class), any(), any(), any(), any(),
                    org.mockito.ArgumentMatchers.nullable(BackupTransferChannel.class));
                    });
                try (construction) {
                    ServerOperationGateway gateway = gateway(opened, new AtomicInteger(), Map.of());
                    ServerOperationGateway.Request request = new ServerOperationGateway.Request(ServerTestSupport.REALM, "reader",
                            AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(), Optional.of(evidence),
                            new AdministrativeOperation.Control(new ServerControlOperation.InspectApproval("identity-approval")),
                            new Permission.Resource(Permission.ResourceType.APPROVAL, new Permission.Scope(ServerTestSupport.REALM,
                                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.empty()), Optional.empty(), Optional.empty()),
                            Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(), "identity-correlation");
                    ServerOperationGateway.Outcome outcome = gateway.execute(request, CancellationSignal.NONE);
                    assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class, outcome, outcome.toString());
                    assertEquals(Optional.of(evidence), observed.get().credentialEvidence());
                    assertEquals("reader", observed.get().principalId());
                    assertEquals(scope, authorized.get().scope());
                    ServerOperationGateway.Request embedded = new ServerOperationGateway.Request(request.realmId(), request.principalId(),
                            request.operation(), request.resource(), request.relationship(), request.context(), request.approvalId(), request.correlationId());
                    assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class, gateway.execute(embedded, CancellationSignal.NONE));
                    assertTrue(observed.get().credentialEvidence().isEmpty());
                }
            }
        }
    }

    @Test
    void delegatesAllowedOperationAndDeniesCrossAuthorityWithoutExecution() throws Exception {
        System.out.println("delegatesAllowedOperationAndDeniesCrossAuthorityWithoutExecution");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(ServerTestSupport.grant("read-a", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY, ServerTestSupport.scope(),
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            AtomicInteger calls = new AtomicInteger();
            ServerOperationGateway gateway = gateway(opened, calls, Map.of());
            ServerOperationGateway.Outcome allowed = gateway.execute(request(new PkiOperation.InspectAuthority(
                    ServerTestSupport.AUTHORITY), ServerTestSupport.authorityResource(), Optional.empty()),
                    CancellationSignal.NONE);
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, allowed);
            Permission.Scope otherScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(new PkiId("ca-b")), Optional.empty(), Optional.empty());
            Permission.Resource forged = new Permission.Resource(Permission.ResourceType.AUTHORITY, otherScope,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty());
            ServerOperationGateway.Outcome denied = gateway.execute(request(new PkiOperation.InspectAuthority(
                    ServerTestSupport.AUTHORITY), forged, Optional.empty()), CancellationSignal.NONE);
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, denied);
            assertEquals(1, calls.get());
            System.out.println("...backend-calls=" + calls.get());
        }
        System.out.println("...ok");
    }

    @Test
    void authorizesPendingConfirmationQueryOnlyForItsExactAuthorityScope() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(ServerTestSupport.grant("confirmation-search", "auditor",
                    Permission.Effect.ALLOW, Permission.Action.CERTIFICATE_SEARCH,
                    Permission.ResourceType.CERTIFICATE, ServerTestSupport.scope(),
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            AtomicInteger calls = new AtomicInteger();
            ServerOperationGateway gateway = gateway(opened, calls, Map.of());
            PkiOperation operation = new PkiOperation.ListPendingCredentialConfirmations(
                    ServerTestSupport.AUTHORITY, Optional.empty(),
                    java.time.Instant.parse("2026-08-30T12:00:00Z"), Optional.empty(), 100);
            Permission.Resource exact = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                    ServerTestSupport.scope(), Optional.empty(), Optional.empty());
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(request(operation, exact, Optional.empty()), CancellationSignal.NONE));

            Permission.Scope otherScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(new PkiId("ca-b")), Optional.empty(), Optional.empty());
            Permission.Resource forged = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                    otherScope, Optional.empty(), Optional.empty());
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    gateway.execute(request(operation, forged, Optional.empty()), CancellationSignal.NONE));
            assertEquals(1, calls.get());
        }
    }

    @Test
    void resolvesChallengeResourceBeforeAuthorizationAndExecutesOnlyForExactGrant() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            Permission.Scope exactScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.of("profile-a"));
            opened.store().createGrant(ServerTestSupport.grant("confirmation-challenge", "auditor",
                    Permission.Effect.ALLOW, Permission.Action.CERTIFICATE_PUBLICATION_CHANGE,
                    Permission.ResourceType.CERTIFICATE, exactScope, Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED));
            opened.store().createPrincipal(ServerTestSupport.principal("wrong-profile"));
            Permission.Scope wrongProfileScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.of("profile-b"));
            opened.store().createGrant(ServerTestSupport.grant("wrong-profile-challenge", "wrong-profile",
                    Permission.Effect.ALLOW, Permission.Action.CERTIFICATE_PUBLICATION_CHANGE,
                    Permission.ResourceType.CERTIFICATE, wrongProfileScope, Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED));
            AtomicInteger calls = new AtomicInteger();
            AtomicInteger scopeLookups = new AtomicInteger();
            PkiResourceScopeResolver scopes = new TestScopeResolver() {
                @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                    scopeLookups.incrementAndGet();
                    return super.credentialScope(credentialId);
                }
            };
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())), scopes);
            PkiOperation operation = new PkiOperation.IssueCredentialConfirmationChallenge(
                    new PkiId("credential-a"));
            Permission.Resource transportResource = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                    ServerTestSupport.scope(), Optional.of(new PkiId("credential-a")), Optional.empty());

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(request(operation, transportResource, Optional.empty()),
                            CancellationSignal.NONE));
            assertEquals(1, scopeLookups.get());

            Permission.Scope wrongAuthority = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(new PkiId("ca-b")), Optional.empty(), Optional.empty());
            Permission.Resource forged = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                    wrongAuthority, Optional.of(new PkiId("credential-a")), Optional.empty());
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    gateway.execute(request(operation, forged, Optional.empty()), CancellationSignal.NONE));

            ServerOperationGateway.Request wrongProfileGrant = new ServerOperationGateway.Request(
                    ServerTestSupport.REALM, "wrong-profile", operation, transportResource,
                    Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(),
                    "correlation-wrong-profile");
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    gateway.execute(wrongProfileGrant, CancellationSignal.NONE));

            PkiResourceScopeResolver missing = new TestScopeResolver() {
                @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                    return Optional.empty();
                }
            };
            ServerOperationGateway unavailable = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())), missing);
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    unavailable.execute(request(operation, transportResource, Optional.empty()),
                            CancellationSignal.NONE));
            assertEquals(1, calls.get());
        }
    }

    @Test
    void completesProofOnlyAfterExactAuthoritativeScopeAuthorization() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            Permission.Scope exactScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.of("profile-a"));
            opened.store().createGrant(ServerTestSupport.grant("confirmation-complete", "auditor",
                    Permission.Effect.ALLOW, Permission.Action.CERTIFICATE_CONFIRM,
                    Permission.ResourceType.CERTIFICATE, exactScope, Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED));
            opened.store().createPrincipal(ServerTestSupport.principal("wrong-profile"));
            Permission.Scope wrongProfileScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.of("profile-b"));
            opened.store().createGrant(ServerTestSupport.grant("wrong-profile-complete", "wrong-profile",
                    Permission.Effect.ALLOW, Permission.Action.CERTIFICATE_CONFIRM,
                    Permission.ResourceType.CERTIFICATE, wrongProfileScope, Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED));
            AtomicInteger calls = new AtomicInteger();
            AtomicInteger scopeLookups = new AtomicInteger();
            PkiResourceScopeResolver scopes = new TestScopeResolver() {
                @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                    scopeLookups.incrementAndGet();
                    return super.credentialScope(credentialId);
                }
            };
            List<AuditEvent> events = new java.util.ArrayList<>();
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())), scopes,
                    new AtomicReference<>(), events::add);
            PkiOperation operation = completionOperation(new byte[] {1, 2, 3, 4});
            Permission.Resource transportResource = credentialResource(new PkiId("credential-a"));

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(request(operation, transportResource, Optional.empty()),
                            CancellationSignal.NONE));
            assertEquals(1, scopeLookups.get());
            assertEquals(1, calls.get());

            Permission.Scope wrongAuthority = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(new PkiId("ca-b")), Optional.empty(), Optional.empty());
            Permission.Resource forged = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                    wrongAuthority, Optional.of(new PkiId("credential-a")), Optional.empty());
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    gateway.execute(request(operation, forged, Optional.empty()), CancellationSignal.NONE));
            ServerOperationGateway.Request wrongProfileGrant = new ServerOperationGateway.Request(
                    ServerTestSupport.REALM, "wrong-profile", operation, transportResource,
                    Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(),
                    "correlation-wrong-profile");
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    gateway.execute(wrongProfileGrant, CancellationSignal.NONE));

            PkiResourceScopeResolver missing = new TestScopeResolver() {
                @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                    return Optional.empty();
                }
            };
            ServerOperationGateway unavailable = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())), missing);
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    unavailable.execute(request(operation, transportResource, Optional.empty()),
                            CancellationSignal.NONE));
            assertEquals(1, calls.get());

            String encodedResponse = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(new byte[] {1, 2, 3, 4});
            assertFalse(operation.toString().contains(encodedResponse));
            assertFalse(events.toString().contains(encodedResponse));
            OperationSecurityDescriptors descriptors = new OperationSecurityDescriptors();
            Permission.Resource authoritative = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                    exactScope, Optional.of(new PkiId("credential-a")), Optional.empty());
            assertNotEquals(descriptors.commitment(ServerTestSupport.REALM, operation, authoritative),
                    descriptors.commitment(ServerTestSupport.REALM,
                            completionOperation(new byte[] {1, 2, 3, 5}), authoritative));
        }
    }

    @Test
    void requiresExactApprovalForHighRiskOperationAndExecutesOnce() throws Exception {
        System.out.println("requiresExactApprovalForHighRiskOperationAndExecutesOnce");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("officer"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver"));
            Permission.Scope realmScope = new Permission.Scope(ServerTestSupport.REALM, Optional.empty(),
                    Optional.empty(), Optional.empty());
            opened.store().createGrant(ServerTestSupport.grant("create", "officer", Permission.Effect.ALLOW,
                    Permission.Action.AUTHORITY_CREATE, Permission.ResourceType.AUTHORITY, realmScope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            ApprovalService.Policy policy = new ApprovalService.Policy("high-risk", 1, Set.of("approver"),
                    Set.of(), true, Duration.ofHours(1), true);
            AtomicInteger calls = new AtomicInteger();
            AtomicReference<RevocationExecutionEvidence> evidence = new AtomicReference<>();
            ServerOperationGateway gateway = gateway(opened, calls, evidence,
                    Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, policy));
            PkiSigningOperation operation = new PkiSigningOperation.CreateAuthority(new zeroecho.pki.api.FormatId("x509"),
                    new zeroecho.pki.api.SubjectRef("subject-a"), "profile-a", new zeroecho.pki.api.KeyRef("key-a"));
            Permission.Resource resource = new Permission.Resource(Permission.ResourceType.AUTHORITY, realmScope,
                    Optional.empty(), Optional.empty());
            ServerOperationGateway.Request initial = request(operation, resource, Optional.empty());
            ServerOperationGateway.Outcome required = gateway.execute(initial, CancellationSignal.NONE);
            String commitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    required).operationCommitment();
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            approvals.request("approval-gateway", operation.name(), commitment, realmScope, "officer", policy);
            approvals.decide("approval-gateway", "approver",
                    ApprovalService.Choice.APPROVE, "reviewed");
            ServerOperationGateway.Outcome executed = gateway.execute(request(operation, resource,
                    Optional.of("approval-gateway")), CancellationSignal.NONE);
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, executed);
            assertThrows(IllegalStateException.class, () -> gateway.execute(request(operation, resource,
                    Optional.of("approval-gateway")), CancellationSignal.NONE));
            assertEquals(1, calls.get());
            System.out.println("...approval-state=" + approvals.requireCurrent("approval-gateway").state());
        }
        System.out.println("...ok");
    }

    @Test
    void renewCredentialCoCommitsResolvedIssuanceEvidence() throws Exception {
        System.out.println("renewCredentialCoCommitsResolvedIssuanceEvidence");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(ServerTestSupport.grant("renew", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.CERTIFICATE_RENEW, Permission.ResourceType.CERTIFICATE,
                    ServerTestSupport.scope(), Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED));
            AtomicInteger calls = new AtomicInteger();
            AtomicReference<zeroecho.pki.api.attr.AttributeSet> issuanceEvidence = new AtomicReference<>();
            PkiOperationOutcome success = new PkiOperationOutcome.Completed(new PkiOperationResult("test",
                    Map.of("safe", new PkiOperationValue.BooleanValue(true))));
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(), success, new TestScopeResolver(),
                    new AtomicReference<>(), opened.audit(), () -> { }, issuanceEvidence);
            PkiId credentialId = new PkiId("cred-renew");
            PkiSigningOperation operation = new PkiSigningOperation.RenewCredential(credentialId);
            ServerOperationGateway.Outcome executed = gateway.execute(
                    request(operation, credentialResource(credentialId), Optional.empty()), CancellationSignal.NONE);
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, executed);
            // The renewed credential co-commits the same issuance evidence as a fresh issuance: gateway actor
            // context plus the target credential's AUTHORITATIVE issuer/profile resolved by the scope resolver.
            zeroecho.pki.application.IssuanceExecutionEvidence evidence =
                    zeroecho.pki.application.IssuanceExecutionEvidence.decode(issuanceEvidence.get()).orElseThrow();
            assertEquals("auditor", evidence.actorId());
            assertEquals(ServerTestSupport.AUTHORITY.value(), evidence.issuerCaId());
            assertEquals("profile-a", evidence.profileId());
            assertEquals(zeroecho.pki.application.IssuanceExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                    evidence.authorizationPath().orElseThrow());
            assertEquals(zeroecho.pki.application.IssuanceExecutionEvidence.Outcome.ISSUED, evidence.outcome());
        }
        System.out.println("...ok");
    }

    @Test
    void acmeDirectoryApprovalRejectsActiveProfileDriftBeforeExecution() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("officer"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver"));
            Permission.Scope scope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.of("server-tls"));
            opened.store().createGrant(ServerTestSupport.grant("acme-manage", "officer", Permission.Effect.ALLOW,
                    Permission.Action.ACME_DIRECTORY_MANAGE, Permission.ResourceType.ACME_DIRECTORY, scope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            ApprovalService.Policy approvalPolicy = new ApprovalService.Policy("high-risk", 1,
                    Set.of("approver"), Set.of(), true, Duration.ofHours(1), true);
            ServerOperationGateway gateway = gateway(opened, new AtomicInteger(),
                    Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, approvalPolicy));
            AcmeService acme = mock(AcmeService.class);
            gateway.installAcme(acme);
            AcmeService.DirectoryRegistration registration = new AcmeService.DirectoryRegistration(
                    "internal", ServerTestSupport.AUTHORITY, "server-tls", "acme-enrollment", Set.of("example.test"),
                    Duration.ofDays(30), Set.of("RSA"), Set.of("STANDARD_ONLY"),
                    Set.of(AcmeState.ChallengeType.HTTP_01), Set.of("http"), Optional.empty(), false);
            ServerControlOperation.RegisterAcmeDirectory operation =
                    new ServerControlOperation.RegisterAcmeDirectory(registration);
            CertificateProfileRef firstProfile = new CertificateProfileRef("server-tls", 1L, new byte[32]);
            byte[] newerHash = new byte[32];
            java.util.Arrays.fill(newerHash, (byte) 1);
            CertificateProfileRef newerProfile = new CertificateProfileRef("server-tls", 2L, newerHash);
            AtomicReference<ServerControlOperation.AcmeDirectoryProfilePrecondition> current =
                    new AtomicReference<>(new ServerControlOperation.AcmeDirectoryProfilePrecondition(
                            firstProfile, "1".repeat(64)));
            when(acme.resolveDirectoryProfilePrecondition(registration)).thenAnswer(ignored -> current.get());
            Permission.Resource resource = new Permission.Resource(Permission.ResourceType.ACME_DIRECTORY, scope,
                    Optional.empty(), Optional.empty());

            String approvedCommitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    gateway.execute(controlRequest("officer", operation, resource, Optional.empty()),
                            CancellationSignal.NONE)).operationCommitment();
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK,
                    opened.audit());
            approvals.request("approval-acme-profile", operation.name(), approvedCommitment, scope,
                    "officer", approvalPolicy);
            approvals.decide("approval-acme-profile", "approver", ApprovalService.Choice.APPROVE, "reviewed");
            current.set(new ServerControlOperation.AcmeDirectoryProfilePrecondition(
                    newerProfile, "2".repeat(64)));

            assertThrows(IllegalStateException.class, () -> gateway.execute(controlRequest("officer", operation,
                    resource, Optional.of("approval-acme-profile")), CancellationSignal.NONE));
            String driftedCommitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    gateway.execute(controlRequest("officer", operation, resource, Optional.empty()),
                            CancellationSignal.NONE)).operationCommitment();
            assertNotEquals(approvedCommitment, driftedCommitment);
            verify(acme, never()).registerDirectory(any(), any());
        }
    }

    @Test
    void conditionalRevocationApprovalBindsJustificationAndCannotBeReused() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver"));
            opened.store().createGrant(revocationGrant("conditional-revoke",
                    Set.of(Permission.Condition.APPROVAL_REQUIRED)));
            opened.store().createGrant(ServerTestSupport.grant("request-approval", "auditor",
                    Permission.Effect.ALLOW, Permission.Action.REQUEST_SUBMIT,
                    Permission.ResourceType.APPROVAL, ServerTestSupport.scope(), Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED));
            ApprovalService.Policy policy = new ApprovalService.Policy("high-risk", 1, Set.of("approver"),
                    Set.of(), true, Duration.ofHours(1), true);
            AtomicInteger calls = new AtomicInteger();
            AtomicInteger wakes = new AtomicInteger();
            AtomicReference<RevocationExecutionEvidence> evidence = new AtomicReference<>();
            ServerOperationGateway gateway = gateway(opened, calls,
                    Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, policy),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver(), evidence, opened.audit(), () -> {
                        wakes.incrementAndGet();
                        throw new IllegalStateException("test wake failure");
                    });
            PkiId credentialId = new PkiId("credential-a");
            Permission.Resource resource = credentialResource(credentialId);
            PkiOperation first = new PkiOperation.RevokeCredential(credentialId,
                    RevocationReason.KEY_COMPROMISE, Optional.of("ticket-100"));
            PkiOperation changed = new PkiOperation.RevokeCredential(credentialId,
                    RevocationReason.KEY_COMPROMISE, Optional.of("ticket-101"));

            String firstCommitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    gateway.execute(request(first, resource, Optional.empty()), CancellationSignal.NONE))
                    .operationCommitment();
            String changedCommitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                    gateway.execute(request(changed, resource, Optional.empty()), CancellationSignal.NONE))
                    .operationCommitment();
            assertNotEquals(firstCommitment, changedCommitment);
            assertEquals(0, wakes.get());

            ServerControlOperation.RequestApproval approvalRequest = new ServerControlOperation.RequestApproval(
                    "approval-revoke", new AdministrativeOperation.Pki(first), resource);
            Permission.Resource approvalResource = new Permission.Resource(Permission.ResourceType.APPROVAL,
                    resource.scope(), Optional.empty(), Optional.empty());
            ServerOperationGateway.Request requestApproval = new ServerOperationGateway.Request(
                    ServerTestSupport.REALM, "auditor", new AdministrativeOperation.Control(approvalRequest),
                    approvalResource, Permission.Relationship.ANY, Permission.Context.empty(), Optional.empty(),
                    "correlation-approval");
            assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class,
                    gateway.execute(requestApproval, CancellationSignal.NONE));
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK,
                    opened.audit());
            approvals.decide("approval-revoke", "approver", ApprovalService.Choice.APPROVE, "reviewed");
            assertThrows(IllegalStateException.class, () -> gateway.execute(
                    request(changed, resource, Optional.of("approval-revoke")), CancellationSignal.NONE));
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, gateway.execute(
                    request(first, resource, Optional.of("approval-revoke")), CancellationSignal.NONE));
            assertEquals(1, wakes.get());
            assertThrows(IllegalStateException.class, () -> gateway.execute(
                    request(first, resource, Optional.of("approval-revoke")), CancellationSignal.NONE));
            assertEquals(1, calls.get());
            assertEquals(RevocationExecutionEvidence.AuthorizationPath.APPROVAL,
                    evidence.get().authorizationPath().orElseThrow());
            assertEquals(RevocationExecutionEvidence.Authorization.ALLOWED, evidence.get().authorization());
            assertNotEquals("ticket-100", evidence.get().justificationCommitment().orElseThrow());
        }
    }

    @Test
    void rejectsApprovalRequestForUnconditionalRevocationGrant() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("direct-revoke", Set.of()));
            opened.store().createGrant(approvalRequestGrant());
            ServerOperationGateway gateway = gateway(opened, new AtomicInteger(), approvalPolicies());
            PkiId credentialId = new PkiId("credential-a");
            PkiOperation operation = new PkiOperation.RevokeCredential(credentialId,
                    RevocationReason.KEY_COMPROMISE, Optional.of("ticket-100"));

            ServerOperationGateway.Outcome outcome = gateway.execute(approvalRequest("approval-unconditional",
                    operation, credentialResource(credentialId)), CancellationSignal.NONE);

            assertEquals(AuthorizationEngine.Code.NO_MATCHING_GRANT,
                    assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, outcome).code());
            assertThrows(IllegalArgumentException.class,
                    () -> opened.store().requireApproval("approval-unconditional"));
        }
    }

    @Test
    void rejectsApprovalRequestWhenJustificationConditionRemainsUnsatisfied() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("conditional-justified-revoke",
                    Set.of(Permission.Condition.REASON_REQUIRED, Permission.Condition.APPROVAL_REQUIRED)));
            opened.store().createGrant(approvalRequestGrant());
            ServerOperationGateway gateway = gateway(opened, new AtomicInteger(), approvalPolicies());
            PkiId credentialId = new PkiId("credential-a");
            PkiOperation operation = new PkiOperation.RevokeCredential(credentialId,
                    RevocationReason.KEY_COMPROMISE);

            ServerOperationGateway.Outcome outcome = gateway.execute(approvalRequest("approval-unjustified",
                    operation, credentialResource(credentialId)), CancellationSignal.NONE);

            assertEquals(AuthorizationEngine.Code.NO_MATCHING_GRANT,
                    assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, outcome).code());
            assertThrows(IllegalArgumentException.class,
                    () -> opened.store().requireApproval("approval-unjustified"));
        }
    }

    @Test
    void rejectsApprovalRequestForWrongOrUnresolvedCredentialAuthority() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("conditional-revoke",
                    Set.of(Permission.Condition.APPROVAL_REQUIRED)));
            opened.store().createGrant(approvalRequestGrant());
            zeroecho.pki.application.PkiResourceScopeResolver invalidAuthorities = new TestScopeResolver() {
                @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                    return credentialId.value().equals("credential-wrong")
                            ? Optional.of(new CredentialScope(new PkiId("ca-b"), "profile-a"))
                            : Optional.empty();
                }
            };
            ServerOperationGateway gateway = gateway(opened, new AtomicInteger(), approvalPolicies(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    invalidAuthorities);
            PkiId wrong = new PkiId("credential-wrong");
            PkiId unresolved = new PkiId("credential-unresolved");

            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, gateway.execute(
                    approvalRequest("approval-wrong", new PkiOperation.RevokeCredential(wrong,
                            RevocationReason.KEY_COMPROMISE, Optional.of("ticket-100")),
                            credentialResource(wrong)), CancellationSignal.NONE));
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, gateway.execute(
                    approvalRequest("approval-unresolved", new PkiOperation.RevokeCredential(unresolved,
                            RevocationReason.KEY_COMPROMISE, Optional.of("ticket-100")),
                            credentialResource(unresolved)), CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> opened.store().requireApproval("approval-wrong"));
            assertThrows(IllegalArgumentException.class,
                    () -> opened.store().requireApproval("approval-unresolved"));
        }
    }

    @Test
    void revocationCommitmentBindsCredentialReasonAndJustificationPresenceAndValue() {
        OperationSecurityDescriptors descriptors = new OperationSecurityDescriptors();
        PkiId credentialId = new PkiId("credential-a");
        Permission.Resource resource = credentialResource(credentialId);
        PkiOperation.RevokeCredential exact = new PkiOperation.RevokeCredential(credentialId,
                RevocationReason.KEY_COMPROMISE, Optional.of("ticket-100"));
        String commitment = descriptors.commitment(ServerTestSupport.REALM, exact, resource);

        assertEquals(commitment, descriptors.commitment(ServerTestSupport.REALM, exact, resource));
        assertNotEquals(commitment, descriptors.commitment(ServerTestSupport.REALM,
                new PkiOperation.RevokeCredential(credentialId, RevocationReason.KEY_COMPROMISE), resource));
        assertNotEquals(commitment, descriptors.commitment(ServerTestSupport.REALM,
                new PkiOperation.RevokeCredential(credentialId, RevocationReason.KEY_COMPROMISE,
                        Optional.of("ticket-101")), resource));
        assertNotEquals(commitment, descriptors.commitment(ServerTestSupport.REALM,
                new PkiOperation.RevokeCredential(credentialId, RevocationReason.CA_COMPROMISE,
                        Optional.of("ticket-100")), resource));
        PkiId otherCredential = new PkiId("credential-b");
        assertNotEquals(commitment, descriptors.commitment(ServerTestSupport.REALM,
                new PkiOperation.RevokeCredential(otherCredential, RevocationReason.KEY_COMPROMISE,
                        Optional.of("ticket-100")), credentialResource(otherCredential)));
    }

    @Test
    void revocationReasonDoesNotReplaceRequiredOperatorJustification() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("justified-revoke",
                    Set.of(Permission.Condition.REASON_REQUIRED)));
            AtomicInteger calls = new AtomicInteger();
            ServerOperationGateway gateway = gateway(opened, calls, Map.of());
            PkiId credentialId = new PkiId("credential-a");
            Permission.Resource resource = credentialResource(credentialId);
            PkiOperation reasonOnly = new PkiOperation.RevokeCredential(credentialId,
                    RevocationReason.KEY_COMPROMISE);
            Permission.Context forged = new Permission.Context(Optional.of("unbound-context"), false,
                    false, Map.of());
            ServerOperationGateway.Request request = new ServerOperationGateway.Request(ServerTestSupport.REALM,
                    "auditor", reasonOnly, resource, Permission.Relationship.ANY, forged, Optional.empty(),
                    "correlation-a");
            ServerOperationGateway.Outcome denied = gateway.execute(request, CancellationSignal.NONE);
            assertEquals(AuthorizationEngine.Code.CONDITION_NOT_SATISFIED,
                    assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, denied).code());

            PkiOperation justified = new PkiOperation.RevokeCredential(credentialId,
                    RevocationReason.KEY_COMPROMISE, Optional.of("ticket-100"));
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(request(justified, resource, Optional.empty()), CancellationSignal.NONE));
            assertEquals(1, calls.get());
        }
    }

    @Test
    void revocationWithoutApprovalConditionExecutesDirectly() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("direct-revoke", Set.of()));
            AtomicInteger calls = new AtomicInteger();
            AtomicInteger wakes = new AtomicInteger();
            AtomicReference<RevocationExecutionEvidence> evidence = new AtomicReference<>();
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver(), evidence, opened.audit(), wakes::incrementAndGet);
            PkiId credentialId = new PkiId("credential-a");
            PkiOperation operation = new PkiOperation.RevokeCredential(credentialId,
                    RevocationReason.KEY_COMPROMISE);
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, gateway.execute(
                    request(operation, credentialResource(credentialId), Optional.empty()),
                    CancellationSignal.NONE));
            assertEquals(1, calls.get());
            assertEquals(RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                    evidence.get().authorizationPath().orElseThrow());
            assertEquals("auditor", evidence.get().actorId());
            assertEquals("correlation-a", evidence.get().requestId());
            assertEquals(1, wakes.get());
        }
    }

    @Test
    void pendingConfirmationRevocationUsesExactScopeRevokePermissionAndBoundEvidence()
            throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("pending-confirmation-revoke", Set.of()));
            AtomicInteger calls = new AtomicInteger();
            AtomicInteger lookups = new AtomicInteger();
            AtomicReference<RevocationExecutionEvidence> evidence = new AtomicReference<>();
            PkiResourceScopeResolver scopes = new TestScopeResolver() {
                @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                    lookups.incrementAndGet();
                    return super.credentialScope(credentialId);
                }
            };
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    scopes, evidence);
            PkiId credentialId = new PkiId("credential-a");
            PkiOperation.RevokePendingCredentialConfirmation operation =
                    new PkiOperation.RevokePendingCredentialConfirmation(
                            credentialId, Optional.of("ticket-200"));

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, gateway.execute(
                    request(operation, credentialResource(credentialId), Optional.empty()),
                    CancellationSignal.NONE));

            assertEquals(1, calls.get());
            assertEquals(1, lookups.get());
            assertEquals("auditor", evidence.get().actorId());
            assertEquals(RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                    evidence.get().authorizationPath().orElseThrow());
            assertEquals(RevocationExecutionEvidence.commitJustification(Optional.of("ticket-200")),
                    evidence.get().justificationCommitment().orElseThrow());
            OperationSecurityDescriptors descriptors = new OperationSecurityDescriptors();
            Permission.Scope exactScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.of("profile-a"));
            Permission.Resource exactResource = new Permission.Resource(
                    Permission.ResourceType.CERTIFICATE, exactScope,
                    Optional.of(credentialId), Optional.empty());
            assertNotEquals(descriptors.commitment(ServerTestSupport.REALM, operation, exactResource),
                    descriptors.commitment(ServerTestSupport.REALM,
                            new PkiOperation.RevokePendingCredentialConfirmation(
                                    credentialId, Optional.of("ticket-201")), exactResource));
        }
    }

    @Test
    void pendingConfirmationApprovalReconstructsNestedAndExecutionScopesWithOneLookupEach()
            throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver"));
            opened.store().createGrant(revocationGrant("pending-confirmation-approved",
                    Set.of(Permission.Condition.APPROVAL_REQUIRED)));
            opened.store().createGrant(approvalRequestGrant());
            AtomicInteger calls = new AtomicInteger();
            AtomicInteger lookups = new AtomicInteger();
            AtomicReference<RevocationExecutionEvidence> evidence = new AtomicReference<>();
            PkiResourceScopeResolver scopes = new TestScopeResolver() {
                @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                    lookups.incrementAndGet();
                    return super.credentialScope(credentialId);
                }
            };
            ServerOperationGateway gateway = gateway(opened, calls, approvalPolicies(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    scopes, evidence);
            PkiId credentialId = new PkiId("credential-a");
            PkiOperation.RevokePendingCredentialConfirmation operation =
                    new PkiOperation.RevokePendingCredentialConfirmation(credentialId);
            Permission.Resource omittedProfile = credentialResource(credentialId);

            assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class,
                    gateway.execute(approvalRequest("approval-pending-confirmation",
                            operation, omittedProfile), CancellationSignal.NONE));
            assertEquals(1, lookups.get());
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK,
                    opened.audit());
            assertEquals(Optional.of("profile-a"), approvals.requireCurrent(
                    "approval-pending-confirmation").scope().profileId());
            approvals.decide("approval-pending-confirmation", "approver",
                    ApprovalService.Choice.APPROVE, "reviewed");

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    gateway.execute(request(operation, omittedProfile,
                            Optional.of("approval-pending-confirmation")),
                            CancellationSignal.NONE));
            assertEquals(2, lookups.get());
            assertEquals(1, calls.get());
            assertEquals(RevocationExecutionEvidence.AuthorizationPath.APPROVAL,
                    evidence.get().authorizationPath().orElseThrow());

            Permission.Scope spoofedScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(),
                    Optional.of("wrong-profile"));
            Permission.Resource spoofed = new Permission.Resource(
                    Permission.ResourceType.CERTIFICATE, spoofedScope,
                    Optional.of(credentialId), Optional.empty());
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, gateway.execute(
                    approvalRequest("approval-spoofed-profile", operation, spoofed),
                    CancellationSignal.NONE));
            assertEquals(3, lookups.get());
            assertEquals(1, calls.get());
        }
    }

    @Test
    void revocationWakeIgnoresDeniedUnrelatedAndNoncompletedOutcomes() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("direct-revoke", Set.of()));
            opened.store().createGrant(ServerTestSupport.grant("read-a", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY, ServerTestSupport.scope(),
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            AtomicInteger wakes = new AtomicInteger();
            PkiId credentialId = new PkiId("credential-a");
            PkiOperation revocation = new PkiOperation.RevokeCredential(credentialId,
                    RevocationReason.KEY_COMPROMISE);
            ServerOperationGateway failed = gateway(opened, new AtomicInteger(), Map.of(),
                    new PkiOperationOutcome.Failed(PkiOperation.RevokeCredential.NAME,
                            PkiOperationFailure.CANCELLED, "TEST_CANCELLED"),
                    new TestScopeResolver(), new AtomicReference<>(), opened.audit(), wakes::incrementAndGet);

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, failed.execute(
                    request(revocation, credentialResource(credentialId), Optional.empty()),
                    CancellationSignal.NONE));
            assertEquals(0, wakes.get());

            ServerOperationGateway pending = gateway(opened, new AtomicInteger(), Map.of(),
                    new PkiOperationOutcome.Pending(PkiOperation.RevokeCredential.NAME, new PkiId("operation-a")),
                    new TestScopeResolver(), new AtomicReference<>(), opened.audit(), wakes::incrementAndGet);
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, pending.execute(
                    request(revocation, credentialResource(credentialId), Optional.empty()),
                    CancellationSignal.NONE));

            ServerOperationGateway completed = gateway(opened, new AtomicInteger(), Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver(), new AtomicReference<>(), opened.audit(), wakes::incrementAndGet);
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, completed.execute(request(
                    new PkiOperation.InspectAuthority(ServerTestSupport.AUTHORITY),
                    ServerTestSupport.authorityResource(), Optional.empty()), CancellationSignal.NONE));
            Permission.Scope otherScope = new Permission.Scope(ServerTestSupport.REALM,
                    Optional.of(new PkiId("ca-b")), Optional.empty(), Optional.empty());
            Permission.Resource forged = new Permission.Resource(Permission.ResourceType.CERTIFICATE, otherScope,
                    Optional.of(credentialId), Optional.empty());
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, completed.execute(
                    request(revocation, forged, Optional.empty()), CancellationSignal.NONE));
            assertEquals(0, wakes.get());
        }
    }

    @Test
    void throwingImmediateAuditCannotChangeCommittedAdministrativeRevocationOutcome() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("direct-revoke", Set.of()));
            AtomicInteger calls = new AtomicInteger();
            AtomicReference<RevocationExecutionEvidence> evidence = new AtomicReference<>();
            AuditSink throwingAudit = event -> {
                throw new IllegalStateException("immediate audit unavailable");
            };
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver(), evidence, throwingAudit);
            PkiId credentialId = new PkiId("credential-a");

            ServerOperationGateway.Outcome outcome = gateway.execute(request(
                    new PkiOperation.RevokeCredential(credentialId, RevocationReason.KEY_COMPROMISE),
                    credentialResource(credentialId), Optional.empty()), CancellationSignal.NONE);

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, outcome);
            assertEquals(1, calls.get());
            assertEquals(RevocationExecutionEvidence.Outcome.COMMITTED, evidence.get().outcome());
        }
    }

    @Test
    void classifiesBreakGlassBeforeOtherAdministrativePaths() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createPrincipal(ServerTestSupport.principal("issuer"));
            Permission.Grant emergency = revocationGrant("emergency-revoke", Set.of());
            opened.store().createBreakGlass(new BreakGlassService.Record("break-revoke", "auditor", emergency,
                    "incident", "issuer", Optional.empty(), ServerTestSupport.CLOCK.instant(),
                    ServerTestSupport.CLOCK.instant(), ServerTestSupport.CLOCK.instant().plus(Duration.ofHours(1)),
                    BreakGlassService.State.ACTIVE, "a".repeat(64)));
            AtomicInteger calls = new AtomicInteger();
            AtomicReference<RevocationExecutionEvidence> evidence = new AtomicReference<>();
            ServerOperationGateway gateway = gateway(opened, calls, evidence, Map.of());
            PkiId credentialId = new PkiId("credential-a");

            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, gateway.execute(request(
                    new PkiOperation.RevokeCredential(credentialId, RevocationReason.KEY_COMPROMISE),
                    credentialResource(credentialId), Optional.empty()), CancellationSignal.NONE));

            assertEquals(1, calls.get());
            assertEquals(RevocationExecutionEvidence.AuthorizationPath.BREAK_GLASS,
                    evidence.get().authorizationPath().orElseThrow());
        }
    }

    @Test
    void failsClosedWhenRevocationEvidenceIsUnsupported() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("direct-revoke", Set.of()));
            AuthorizationEngine authorization = new AuthorizationEngine(ServerTestSupport.CLOCK);
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK,
                    opened.audit());
            BreakGlassService breakGlass = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK,
                    opened.audit());
            DisclosureService disclosure = new DisclosureService(ServerTestSupport.REALM, opened.store(),
                    DisclosureService.Defaults.recommended(), ServerTestSupport.CLOCK, new SecureRandom(),
                    opened.audit());
            AuditorViews auditorViews = new AuditorViews(ServerTestSupport.CLOCK, opened.audit());
            CredentialPublicationGate publication = new CredentialPublicationGate(mock(PkiRepository.class),
                    mock(ProfileService.class), mock(CredentialConfirmationService.class), disclosure,
                    ServerTestSupport.CLOCK, () -> { });
            ServerOperationGateway gateway = new ServerOperationGateway(ServerTestSupport.REALM,
                    new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                    opened.store(), RoleTemplateCatalog.load(getClass().getClassLoader()), authorization, approvals,
                    breakGlass, disclosure, publication, auditorViews, Optional.empty(),
                    new OperationSecurityDescriptors(), (operation, cancellation) ->
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    (request, evidence, cancellation) -> { throw new AssertionError("Unexpected signing"); },
                    new TestScopeResolver(), Map.of(),
                    profileId -> zeroecho.pki.api.profile.IssuanceApprovalRequirement.NONE,
                    ServerTestSupport.CLOCK, opened.audit(), () -> { });
            PkiId credentialId = new PkiId("credential-a");

            assertThrows(IllegalStateException.class, () -> gateway.execute(request(
                    new PkiOperation.RevokeCredential(credentialId, RevocationReason.KEY_COMPROMISE),
                    credentialResource(credentialId), Optional.empty()), CancellationSignal.NONE));
        }
    }

    @Test
    void preservesRecoveryAndExternalOutcomeClassifications() throws Exception {
        System.out.println("preservesRecoveryAndExternalOutcomeClassifications");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(ServerTestSupport.grant("read", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY, ServerTestSupport.scope(),
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            PkiOperationOutcome recovery = new PkiOperationOutcome.Failed(PkiOperation.InspectAuthority.NAME,
                    PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
            ServerOperationGateway gateway = gateway(opened, new AtomicInteger(), Map.of(), recovery);
            ServerOperationGateway.Outcome outcome = gateway.execute(request(new PkiOperation.InspectAuthority(
                    ServerTestSupport.AUTHORITY), ServerTestSupport.authorityResource(), Optional.empty()),
                    CancellationSignal.NONE);
            PkiOperationOutcome exact = assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    outcome).outcome();
            assertEquals(PkiOperationFailure.RECOVERY_REQUIRED,
                    assertInstanceOf(PkiOperationOutcome.Failed.class, exact).classification());
            System.out.println("...classification=RECOVERY_REQUIRED");
        }
        System.out.println("...ok");
    }

    @Test
    void rejectsCredentialWhoseAuthoritativeIssuerDiffersFromClaimedScope() throws Exception {
        System.out.println("rejectsCredentialWhoseAuthoritativeIssuerDiffersFromClaimedScope");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(ServerTestSupport.grant("credential-read", "auditor",
                    Permission.Effect.ALLOW, Permission.Action.CERTIFICATE_READ_METADATA,
                    Permission.ResourceType.CERTIFICATE, ServerTestSupport.scope(), Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED));
            AtomicInteger calls = new AtomicInteger();
            zeroecho.pki.application.PkiResourceScopeResolver otherAuthority = new TestScopeResolver() {
                @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                    return Optional.of(new CredentialScope(new PkiId("ca-b"), "profile-a"));
                }
            };
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("credential.inspect", Map.of())),
                    otherAuthority);
            PkiId credentialId = new PkiId("credential-a");
            Permission.Resource resource = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                    ServerTestSupport.scope(), Optional.of(credentialId), Optional.empty());
            ServerOperationGateway.Outcome outcome = gateway.execute(request(
                    new PkiOperation.InspectCredential(credentialId), resource, Optional.empty()),
                    CancellationSignal.NONE);
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, outcome);
            assertEquals(0, calls.get());
            System.out.println("...cross-authority-backend-calls=" + calls.get());
        }
        System.out.println("...ok");
    }

    @Test
    void descriptorRegistryRejectsUnknownAndDuplicateOperations() {
        System.out.println("descriptorRegistryRejectsUnknownAndDuplicateOperations");
        OperationSecurityDescriptors descriptors = new OperationSecurityDescriptors();
        assertEquals(150, descriptors.descriptors().size());
        assertEquals(51, descriptors.descriptors().values().stream()
                .filter(value -> value.family() == OperationSecurityDescriptors.Family.PKI_OPERATION).count());
        assertEquals(10, descriptors.descriptors().values().stream()
                .filter(value -> value.family() == OperationSecurityDescriptors.Family.SIGNING_OPERATION).count());
        assertEquals(descriptors.descriptors().size(), descriptors.descriptors().values().stream()
                .map(OperationSecurityDescriptors.Descriptor::operationId).distinct().count());
        OperationSecurityDescriptors.Descriptor descriptor = descriptors.descriptors()
                .get(PkiOperation.InspectAuthority.NAME);
        OperationSecurityDescriptors limited = new OperationSecurityDescriptors(List.of(descriptor));
        assertThrows(SecurityException.class, () -> limited.require(new PkiOperation.ValidateConfiguration()));
        assertEquals(Permission.ResourceType.CERTIFICATE,
                descriptors.descriptors().get(PkiOperation.RevokeCredential.NAME).resourceType());
        assertEquals(Permission.Action.CERTIFICATE_REVOKE,
                descriptors.descriptors().get(
                        PkiOperation.RevokePendingCredentialConfirmation.NAME).action());
        assertEquals(Permission.ResourceType.REVOCATION,
                descriptors.descriptors().get(PkiOperation.ReadRevocationHistory.NAME).resourceType());
        // Trust-affecting intermediate-CA and issuance-path operations are HIGH_RISK dual-control
        // (owner decision 2026-09-05; see docs/admin-dual-control-operations.md).
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK,
                descriptors.descriptors().get(PkiSigningOperation.CreateIntermediate.NAME).approvalCategory());
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK,
                descriptors.descriptors().get(PkiSigningOperation.IssueIntermediateCertificate.NAME).approvalCategory());
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK,
                descriptors.descriptors().get(PkiOperation.SelectIssuancePath.NAME).approvalCategory());
        assertEquals(OperationSecurityDescriptors.ApprovalCategory.NONE,
                descriptors.descriptors().get(PkiOperation.RegisterIssuerChainPath.NAME).approvalCategory());
        PkiId credentialId = new PkiId("credential-a");
        Permission.Resource legacyResource = new Permission.Resource(Permission.ResourceType.REVOCATION,
                ServerTestSupport.scope(), Optional.of(credentialId), Optional.empty());
        assertThrows(SecurityException.class, () -> descriptors.validateResource(
                new PkiOperation.RevokeCredential(credentialId, RevocationReason.KEY_COMPROMISE), legacyResource));
        assertThrows(IllegalArgumentException.class,
                () -> new OperationSecurityDescriptors(List.of(descriptor, descriptor)));
        System.out.println("...covered-operations=" + descriptors.descriptors().size());
        System.out.println("...ok");
    }

    @Test
    void enforcesResolvedOwningAuthorityForPublicationOperations() throws Exception {
        System.out.println("enforcesResolvedOwningAuthorityForPublicationOperations");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(ServerTestSupport.grant("pub-retry", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.PUBLICATION_RETRY, Permission.ResourceType.PUBLICATION,
                    ServerTestSupport.scope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            opened.store().createGrant(ServerTestSupport.grant("pub-register", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.PUBLICATION_REGISTER, Permission.ResourceType.PUBLICATION,
                    ServerTestSupport.scope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            opened.store().createGrant(ServerTestSupport.grant("pub-reconcile", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.PUBLICATION_RECONCILE, Permission.ResourceType.PUBLICATION,
                    ServerTestSupport.scope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            opened.store().createGrant(approvalRequestGrant());

            PkiOperation retry = new PkiOperation.RetryPublication(new PkiId("pub-a"));
            Permission.Resource retryResource = new Permission.Resource(Permission.ResourceType.PUBLICATION,
                    ServerTestSupport.scope(), Optional.of(new PkiId("pub-a")), Optional.empty());

            // Positive: the declared authority equals the publication's resolved owning authority.
            AtomicInteger calls = new AtomicInteger();
            ServerOperationGateway matching = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver());
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    matching.execute(request(retry, retryResource, Optional.empty()), CancellationSignal.NONE));
            assertEquals(1, calls.get());

            // Negative authorization case: caller holds a valid grant for the declared authority, but the publication is
            // owned by a DIFFERENT authority; the resolved-owner binding must deny it.
            ServerOperationGateway crossOwner = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver() {
                        @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) {
                            return Optional.of(new PkiId("ca-other"));
                        }
                    });
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    crossOwner.execute(request(retry, retryResource, Optional.empty()), CancellationSignal.NONE));

            // Missing owner (unresolved source) fails closed.
            ServerOperationGateway unresolved = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver() {
                        @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) {
                            return Optional.empty();
                        }
                    });
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    unresolved.execute(request(retry, retryResource, Optional.empty()), CancellationSignal.NONE));

            // RegisterPublication resolves the owner directly from its declared immutable source.
            PkiOperation register = new PkiOperation.RegisterPublication(new PkiId("pub-a"),
                    PublicationSourceType.CREDENTIAL, new PkiId("cred-a"),
                    new PublicationTarget(PublicationTargetType.FILESYSTEM, "repo-a"));
            Permission.Resource registerResource = new Permission.Resource(Permission.ResourceType.PUBLICATION,
                    ServerTestSupport.scope(), Optional.of(new PkiId("pub-a")), Optional.empty());
            AtomicInteger registerCalls = new AtomicInteger();
            ServerOperationGateway registerMatching = gateway(opened, registerCalls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver());
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    registerMatching.execute(request(register, registerResource, Optional.empty()),
                            CancellationSignal.NONE));
            assertEquals(1, registerCalls.get());

            ServerOperationGateway registerCrossOwner = gateway(opened, registerCalls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver() {
                        @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                            return Optional.of(new CredentialScope(new PkiId("ca-other"), "profile-a"));
                        }
                    });
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    registerCrossOwner.execute(request(register, registerResource, Optional.empty()),
                            CancellationSignal.NONE));

            // RegisterPublication with a STATUS_OBJECT source resolves the owner via statusObjectAuthority.
            PkiOperation registerStatus = new PkiOperation.RegisterPublication(new PkiId("pub-a"),
                    PublicationSourceType.STATUS_OBJECT, new PkiId("status-a"),
                    new PublicationTarget(PublicationTargetType.FILESYSTEM, "repo-a"));
            AtomicInteger statusCalls = new AtomicInteger();
            ServerOperationGateway registerStatusMatching = gateway(opened, statusCalls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver());
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    registerStatusMatching.execute(request(registerStatus, registerResource, Optional.empty()),
                            CancellationSignal.NONE));
            assertEquals(1, statusCalls.get());

            // ReconcilePublication is bound to the committed record's resolved owner.
            PkiOperation reconcile = new PkiOperation.ReconcilePublication(new PkiId("pub-a"));
            ServerOperationGateway reconcileCrossOwner = gateway(opened, new AtomicInteger(), Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver() {
                        @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) {
                            return Optional.of(new PkiId("ca-other"));
                        }
                    });
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    reconcileCrossOwner.execute(request(reconcile, retryResource, Optional.empty()),
                            CancellationSignal.NONE));

            // A CREDENTIAL source that is not an end-entity credential (credentialScope throws
            // IllegalStateException) fails closed as a uniform denial, never an unclassified error.
            ServerOperationGateway nonEndEntitySource = gateway(opened, new AtomicInteger(), Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver() {
                        @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                            throw new IllegalStateException("Credential is not bound to an end-entity profile");
                        }
                    });
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    nonEndEntitySource.execute(request(register, registerResource, Optional.empty()),
                            CancellationSignal.NONE));

            // The approval-request target path (second choke point) also binds the resolved owner.
            ServerOperationGateway approvalCrossOwner = gateway(opened, new AtomicInteger(), approvalPolicies(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver() {
                        @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) {
                            return Optional.of(new PkiId("ca-other"));
                        }
                    });
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                    approvalCrossOwner.execute(approvalRequest("approval-pub-cross", retry, retryResource),
                            CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class,
                    () -> opened.store().requireApproval("approval-pub-cross"));
        }
        System.out.println("...ok");
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies) {
        PkiOperationOutcome success = new PkiOperationOutcome.Completed(new PkiOperationResult("test",
                Map.of("safe", new PkiOperationValue.BooleanValue(true))));
        return gateway(opened, calls, policies, success, new TestScopeResolver(), new AtomicReference<>());
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            AtomicReference<RevocationExecutionEvidence> evidence,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies) {
        PkiOperationOutcome success = new PkiOperationOutcome.Completed(new PkiOperationResult("test",
                Map.of("safe", new PkiOperationValue.BooleanValue(true))));
        return gateway(opened, calls, policies, success, new TestScopeResolver(), evidence);
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result) {
        return gateway(opened, calls, policies, result, new TestScopeResolver(), new AtomicReference<>());
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result, zeroecho.pki.application.PkiResourceScopeResolver resourceScopes) {
        return gateway(opened, calls, policies, result, resourceScopes, new AtomicReference<>());
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result, zeroecho.pki.application.PkiResourceScopeResolver resourceScopes,
            AtomicReference<RevocationExecutionEvidence> evidence) {
        return gateway(opened, calls, policies, result, resourceScopes, evidence, opened.audit());
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result, zeroecho.pki.application.PkiResourceScopeResolver resourceScopes,
            AtomicReference<RevocationExecutionEvidence> evidence, AuditSink auditSink) {
        return gateway(opened, calls, policies, result, resourceScopes, evidence, auditSink, () -> { });
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result, zeroecho.pki.application.PkiResourceScopeResolver resourceScopes,
            AtomicReference<RevocationExecutionEvidence> evidence, AuditSink auditSink, Runnable wake) {
        return gateway(opened, calls, policies, result, resourceScopes, evidence, auditSink, wake,
                new AtomicReference<>());
    }

    @SuppressWarnings("PMD.ExcessiveParameterList") // test wiring mirrors the production gateway dependency graph.
    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result, zeroecho.pki.application.PkiResourceScopeResolver resourceScopes,
            AtomicReference<RevocationExecutionEvidence> evidence, AuditSink auditSink, Runnable wake,
            AtomicReference<zeroecho.pki.api.attr.AttributeSet> issuanceEvidence) {
        return gateway(opened, calls, policies, result, resourceScopes, evidence, auditSink, wake,
                issuanceEvidence, new TestEvidenceExecutor(calls, result, evidence, issuanceEvidence));
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result, zeroecho.pki.application.PkiResourceScopeResolver resourceScopes,
            AtomicReference<RevocationExecutionEvidence> evidence, AuditSink auditSink, Runnable wake,
            AtomicReference<zeroecho.pki.api.attr.AttributeSet> issuanceEvidence,
            zeroecho.pki.application.PkiOperationExecutor executor) {
        AuthorizationEngine authorization = new AuthorizationEngine(ServerTestSupport.CLOCK);
        ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
        BreakGlassService breakGlass = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
        DisclosureService disclosure = new DisclosureService(ServerTestSupport.REALM, opened.store(),
                DisclosureService.Defaults.recommended(), ServerTestSupport.CLOCK, new SecureRandom(), auditSink);
        AuditorViews auditorViews = new AuditorViews(ServerTestSupport.CLOCK, auditSink);
        CredentialPublicationGate publication = new CredentialPublicationGate(mock(PkiRepository.class),
                mock(ProfileService.class), mock(CredentialConfirmationService.class), disclosure,
                ServerTestSupport.CLOCK, () -> { });
        return new ServerOperationGateway(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                opened.store(), RoleTemplateCatalog.load(ServerOperationGatewayTest.class.getClassLoader()),
                authorization, approvals, breakGlass, disclosure, publication, auditorViews, Optional.empty(),
                new OperationSecurityDescriptors(),
                executor,
                (request, exactEvidence, cancellation) -> {
                    exactEvidence.ifPresent(value -> issuanceEvidence.set(value.attributes()));
                    calls.incrementAndGet();
                    return result;
                }, resourceScopes, policies,
                profileId -> zeroecho.pki.api.profile.IssuanceApprovalRequirement.NONE,
                ServerTestSupport.CLOCK, auditSink, wake, () -> { });
    }

    @Test
    void holdAndReleaseRequireTheirOwnPermissionsAndAuthoritativeProfile() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(revocationGrant("revoke-only", Set.of()));
            AtomicInteger calls = new AtomicInteger();
            AtomicInteger wakes = new AtomicInteger();
            AtomicReference<RevocationExecutionEvidence> evidence = new AtomicReference<>();
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of())),
                    new TestScopeResolver(), evidence, opened.audit(), wakes::incrementAndGet);
            PkiId id = new PkiId("credential-a");
            for (PkiOperation operation : List.of(new PkiOperation.HoldCredential(id, Optional.of("ticket")),
                    new PkiOperation.UnholdCredential(id, Optional.of("ticket")))) {
                assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                        gateway.execute(request(operation, credentialResource(id), Optional.empty()), CancellationSignal.NONE));
                Permission.Action action = operation instanceof PkiOperation.HoldCredential
                        ? Permission.Action.CERTIFICATE_HOLD : Permission.Action.CERTIFICATE_RELEASE_HOLD;
                Permission.Scope scope = new Permission.Scope(ServerTestSupport.REALM,
                        Optional.of(ServerTestSupport.AUTHORITY), Optional.empty(), Optional.of("profile-a"));
                opened.store().createGrant(new Permission.Grant(operation.name(), "auditor", Permission.Effect.ALLOW,
                        action, Permission.ResourceType.CERTIFICATE, scope, Permission.Relationship.ANY,
                        Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(), true));
                for (Permission.Scope invalid : List.of(
                        new Permission.Scope(ServerTestSupport.REALM, Optional.of(ServerTestSupport.AUTHORITY),
                                Optional.empty(), Optional.of("wrong-profile")),
                        new Permission.Scope(ServerTestSupport.REALM, Optional.of(new PkiId("other-ca")),
                                Optional.empty(), Optional.of("profile-a")))) {
                    Permission.Resource resource = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                            invalid, Optional.of(id), Optional.empty());
                    assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                            gateway.execute(request(operation, resource, Optional.empty()), CancellationSignal.NONE));
                }
                assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                        gateway.execute(request(operation, credentialResource(id), Optional.empty()), CancellationSignal.NONE));
                assertEquals(RevocationExecutionEvidence.AuthorizationPath.ORDINARY_GRANT,
                        evidence.get().authorizationPath().orElseThrow());
                assertEquals(RevocationExecutionEvidence.commitJustification(Optional.of("ticket")),
                        evidence.get().justificationCommitment().orElseThrow());
            }
            assertEquals(2, calls.get());
            assertEquals(2, wakes.get());
        }
    }

    @Test
    void holdApprovalBindsActionTargetJustificationAndResolvedProfile() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver"));
            for (Permission.Action action : List.of(Permission.Action.CERTIFICATE_HOLD, Permission.Action.CERTIFICATE_RELEASE_HOLD)) {
                opened.store().createGrant(new Permission.Grant(action.name(), "auditor", Permission.Effect.ALLOW,
                        action, Permission.ResourceType.CERTIFICATE, ServerTestSupport.scope(), Permission.Relationship.ANY,
                        Permission.DataView.METADATA_REDACTED, Set.of(Permission.Condition.APPROVAL_REQUIRED), Optional.empty(), true));
            }
            opened.store().createGrant(approvalRequestGrant());
            AtomicInteger calls = new AtomicInteger();
            ServerOperationGateway gateway = gateway(opened, calls, approvalPolicies());
            PkiId id = new PkiId("credential-a");
            PkiOperation operation = new PkiOperation.HoldCredential(id, Optional.of("ticket"));
            assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class,
                    gateway.execute(approvalRequest("approval-hold", operation, credentialResource(id)), CancellationSignal.NONE));
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            assertEquals(Optional.of("profile-a"), approvals.requireCurrent("approval-hold").scope().profileId());
            approvals.decide("approval-hold", "approver", ApprovalService.Choice.APPROVE, "reviewed");
            for (PkiOperation changed : List.of(new PkiOperation.UnholdCredential(id, Optional.of("ticket")),
                    new PkiOperation.HoldCredential(id, Optional.of("changed")),
                    new PkiOperation.HoldCredential(new PkiId("credential-b"), Optional.of("ticket")))) {
                PkiId target = changed instanceof PkiOperation.HoldCredential hold ? hold.credentialId() : id;
                assertThrows(IllegalStateException.class, () -> gateway.execute(
                        request(changed, credentialResource(target), Optional.of("approval-hold")), CancellationSignal.NONE));
            }
            assertEquals(0, calls.get());
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, gateway.execute(
                    request(operation, credentialResource(id), Optional.of("approval-hold")), CancellationSignal.NONE));
            assertEquals(1, calls.get());
        }
    }

    @Test
    void legacyEvidenceExecutorCannotConsumeHoldApproval() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver"));
            opened.store().createGrant(new Permission.Grant("hold", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.CERTIFICATE_HOLD, Permission.ResourceType.CERTIFICATE,
                    ServerTestSupport.scope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED,
                    Set.of(Permission.Condition.APPROVAL_REQUIRED), Optional.empty(), true));
            opened.store().createGrant(approvalRequestGrant());
            AtomicInteger calls = new AtomicInteger();
            PkiOperationOutcome result = new PkiOperationOutcome.Completed(new PkiOperationResult("test", Map.of()));
            class Legacy implements zeroecho.pki.application.PkiOperationExecutor, RevocationEvidenceExecutor {
                @Override public PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation) {
                    calls.incrementAndGet(); return result;
                }
                @Override public PkiOperationOutcome executeRevocation(PkiOperation.RevokeCredential operation,
                        RevocationExecutionEvidence evidence, CancellationSignal cancellation) {
                    calls.incrementAndGet(); return result;
                }
            }
            Legacy legacy = new Legacy();
            assertTrue(!legacy.supportsHoldTransitions());
            ServerOperationGateway unsupported = gateway(opened, calls, approvalPolicies(), result,
                    new TestScopeResolver(), new AtomicReference<>(), opened.audit(), () -> { },
                    new AtomicReference<>(), legacy);
            PkiId id = new PkiId("credential-a");
            PkiOperation operation = new PkiOperation.HoldCredential(id);
            unsupported.execute(approvalRequest("hold-legacy", operation, credentialResource(id)), CancellationSignal.NONE);
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            approvals.decide("hold-legacy", "approver", ApprovalService.Choice.APPROVE, "reviewed");
            ApprovalService.Request before = approvals.requireCurrent("hold-legacy");
            assertThrows(IllegalStateException.class, () -> unsupported.execute(
                    request(operation, credentialResource(id), Optional.of("hold-legacy")), CancellationSignal.NONE));
            assertEquals(before, approvals.requireCurrent("hold-legacy"));
            assertEquals(0, calls.get());
            ServerOperationGateway supported = gateway(opened, calls, approvalPolicies());
            assertInstanceOf(ServerOperationGateway.Outcome.Executed.class, supported.execute(
                    request(operation, credentialResource(id), Optional.of("hold-legacy")), CancellationSignal.NONE));
        }
    }

    private record TestEvidenceExecutor(AtomicInteger calls, PkiOperationOutcome result,
            AtomicReference<RevocationExecutionEvidence> evidence,
            AtomicReference<zeroecho.pki.api.attr.AttributeSet> issuanceEvidence)
            implements zeroecho.pki.application.PkiOperationExecutor, RevocationEvidenceExecutor {
        @Override public boolean supportsHoldTransitions() { return true; }
        @Override public PkiOperationOutcome executeHold(PkiOperation.HoldCredential operation,
                RevocationExecutionEvidence exactEvidence, CancellationSignal cancellation) {
            evidence.set(exactEvidence); calls.incrementAndGet(); return result;
        }
        @Override public PkiOperationOutcome executeUnhold(PkiOperation.UnholdCredential operation,
                RevocationExecutionEvidence exactEvidence, CancellationSignal cancellation) {
            evidence.set(exactEvidence); calls.incrementAndGet(); return result;
        }
        @Override public PkiOperationOutcome execute(PkiOperation operation, CancellationSignal cancellation) {
            calls.incrementAndGet(); return result;
        }
        @Override public PkiOperationOutcome executeRevocation(PkiOperation.RevokeCredential operation,
                RevocationExecutionEvidence exactEvidence, CancellationSignal cancellation) {
            evidence.set(exactEvidence); calls.incrementAndGet(); return result;
        }
        @Override public PkiOperationOutcome executePendingConfirmationRevocation(
                PkiOperation.RevokePendingCredentialConfirmation operation,
                RevocationExecutionEvidence exactEvidence, CancellationSignal cancellation) {
            evidence.set(exactEvidence); calls.incrementAndGet(); return result;
        }
    }

    private static ServerOperationGateway.Request request(PkiOperation operation, Permission.Resource resource,
            Optional<String> approval) {
        String principalId = "auditor";
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, principalId,
                operation, resource, Permission.Relationship.ANY, Permission.Context.empty(), approval,
                "correlation-a");
    }

    private static ServerOperationGateway.Request controlRequest(String principalId,
            PkiSigningOperation operation, Permission.Resource resource, Optional<String> approval) {
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, principalId,
                new AdministrativeOperation.Signing(operation), resource, Permission.Relationship.ANY,
                Permission.Context.empty(), approval, "correlation-control");
    }

    private static ServerOperationGateway.Request request(PkiSigningOperation operation,
            Permission.Resource resource, Optional<String> approval) {
        String principal = operation instanceof PkiSigningOperation.CreateAuthority ? "officer" : "auditor";
        return controlRequest(principal, operation, resource, approval);
    }

    private static ServerOperationGateway.Request controlRequest(String principalId,
            ServerControlOperation operation, Permission.Resource resource, Optional<String> approval) {
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, principalId,
                new AdministrativeOperation.Control(operation), resource, Permission.Relationship.ANY,
                Permission.Context.empty(), approval, "correlation-control");
    }

    private static Permission.Grant revocationGrant(String id, Set<Permission.Condition> conditions) {
        return new Permission.Grant(id, "auditor", Permission.Effect.ALLOW,
                Permission.Action.CERTIFICATE_REVOKE, Permission.ResourceType.CERTIFICATE,
                ServerTestSupport.scope(), Permission.Relationship.ANY,
                Permission.DataView.METADATA_REDACTED, conditions, Optional.empty(), true);
    }

    private static Permission.Grant approvalRequestGrant() {
        return ServerTestSupport.grant("request-approval", "auditor", Permission.Effect.ALLOW,
                Permission.Action.REQUEST_SUBMIT, Permission.ResourceType.APPROVAL, ServerTestSupport.scope(),
                Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED);
    }

    private static Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> approvalPolicies() {
        ApprovalService.Policy policy = new ApprovalService.Policy("high-risk", 1, Set.of("approver"),
                Set.of(), true, Duration.ofHours(1), true);
        return Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, policy);
    }

    private static ServerOperationGateway.Request approvalRequest(String approvalId, PkiOperation operation,
            Permission.Resource targetResource) {
        ServerControlOperation.RequestApproval request = new ServerControlOperation.RequestApproval(approvalId,
                new AdministrativeOperation.Pki(operation), targetResource);
        Permission.Resource approvalResource = new Permission.Resource(Permission.ResourceType.APPROVAL,
                targetResource.scope(), Optional.empty(), Optional.empty());
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, "auditor",
                new AdministrativeOperation.Control(request), approvalResource, Permission.Relationship.ANY,
                Permission.Context.empty(), Optional.empty(), "correlation-approval");
    }

    private static Permission.Resource credentialResource(PkiId credentialId) {
        return new Permission.Resource(Permission.ResourceType.CERTIFICATE, ServerTestSupport.scope(),
                Optional.of(credentialId), Optional.empty());
    }

    private static PkiOperation completionOperation(byte[] response) {
        CredentialConfirmationProofCas proofCas = new CredentialConfirmationProofCas(
                new PkiId("credential-a"), 1L, "a".repeat(64), "b".repeat(64));
        return new PkiOperation.CompleteCredentialConfirmationProof(
                new CredentialConfirmationProofSubmission(proofCas, response));
    }

    private static class TestScopeResolver implements zeroecho.pki.application.PkiResourceScopeResolver {
        @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
            return Optional.of(new CredentialScope(ServerTestSupport.AUTHORITY, "profile-a"));
        }
        @Override public Optional<PkiId> statusObjectAuthority(PkiId statusObjectId) {
            return Optional.of(ServerTestSupport.AUTHORITY);
        }
        @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) {
            return Optional.of(ServerTestSupport.AUTHORITY);
        }
    }
}
