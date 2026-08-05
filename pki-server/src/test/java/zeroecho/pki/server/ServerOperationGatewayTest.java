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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;

/** Gateway descriptor, multi-authority and approval enforcement coverage. */
class ServerOperationGatewayTest {
    @TempDir Path temporaryDirectory;

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
            ServerOperationGateway gateway = gateway(opened, calls,
                    Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, policy));
            PkiOperation operation = new PkiOperation.CreateAuthority(new zeroecho.pki.api.FormatId("x509"),
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
    void preservesRecoveryAndExternalOutcomeClassifications() throws Exception {
        System.out.println("preservesRecoveryAndExternalOutcomeClassifications");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("auditor"));
            opened.store().createGrant(ServerTestSupport.grant("read", "auditor", Permission.Effect.ALLOW,
                    Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY, ServerTestSupport.scope(),
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
            PkiOperationOutcome recovery = new PkiOperationOutcome.Failure(PkiOperation.InspectAuthority.NAME,
                    PkiOperationFailure.RECOVERY_REQUIRED, "RECOVERY_REQUIRED");
            ServerOperationGateway gateway = gateway(opened, new AtomicInteger(), Map.of(), recovery);
            ServerOperationGateway.Outcome outcome = gateway.execute(request(new PkiOperation.InspectAuthority(
                    ServerTestSupport.AUTHORITY), ServerTestSupport.authorityResource(), Optional.empty()),
                    CancellationSignal.NONE);
            PkiOperationOutcome exact = assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    outcome).outcome();
            assertEquals(PkiOperationFailure.RECOVERY_REQUIRED,
                    assertInstanceOf(PkiOperationOutcome.Failure.class, exact).classification());
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
                @Override public Optional<PkiId> credentialAuthority(PkiId credentialId) {
                    return Optional.of(new PkiId("ca-b"));
                }
            };
            ServerOperationGateway gateway = gateway(opened, calls, Map.of(),
                    new PkiOperationOutcome.Success(new PkiOperationResult("credential.inspect", Map.of())),
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
        assertEquals(62, descriptors.descriptors().size());
        assertEquals(16, descriptors.descriptors().values().stream()
                .filter(value -> value.family() == OperationSecurityDescriptors.Family.PKI_OPERATION).count());
        assertThrows(SecurityException.class, () -> descriptors.require(new PkiOperation.ValidateConfiguration()));
        OperationSecurityDescriptors.Descriptor descriptor = descriptors.descriptors()
                .get(PkiOperation.InspectAuthority.NAME);
        assertThrows(IllegalArgumentException.class,
                () -> new OperationSecurityDescriptors(List.of(descriptor, descriptor)));
        System.out.println("...covered-operations=" + descriptors.descriptors().size());
        System.out.println("...ok");
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies) {
        PkiOperationOutcome success = new PkiOperationOutcome.Success(new PkiOperationResult("test",
                Map.of("safe", new PkiOperationValue.BooleanValue(true))));
        return gateway(opened, calls, policies, success, new TestScopeResolver());
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result) {
        return gateway(opened, calls, policies, result, new TestScopeResolver());
    }

    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, AtomicInteger calls,
            Map<OperationSecurityDescriptors.ApprovalCategory, ApprovalService.Policy> policies,
            PkiOperationOutcome result, zeroecho.pki.application.PkiResourceScopeResolver resourceScopes) {
        AuthorizationEngine authorization = new AuthorizationEngine(ServerTestSupport.CLOCK);
        ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
        BreakGlassService breakGlass = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
        return new ServerOperationGateway(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                opened.store(), RoleTemplateCatalog.load(ServerOperationGatewayTest.class.getClassLoader()),
                authorization, approvals, breakGlass, new OperationSecurityDescriptors(),
                (operation, cancellation) -> { calls.incrementAndGet(); return result; }, resourceScopes, policies,
                ServerTestSupport.CLOCK, opened.audit(), () -> { });
    }

    private static ServerOperationGateway.Request request(PkiOperation operation, Permission.Resource resource,
            Optional<String> approval) {
        String principalId = operation instanceof PkiOperation.CreateAuthority ? "officer" : "auditor";
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, principalId,
                operation, resource, Permission.Relationship.ANY, Permission.Context.empty(), approval,
                "correlation-a");
    }

    private static class TestScopeResolver implements zeroecho.pki.application.PkiResourceScopeResolver {
        @Override public Optional<PkiId> credentialAuthority(PkiId credentialId) {
            return Optional.of(ServerTestSupport.AUTHORITY);
        }
        @Override public Optional<PkiId> statusObjectAuthority(PkiId statusObjectId) {
            return Optional.of(ServerTestSupport.AUTHORITY);
        }
        @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) {
            return Optional.of(ServerTestSupport.AUTHORITY);
        }
    }
}
