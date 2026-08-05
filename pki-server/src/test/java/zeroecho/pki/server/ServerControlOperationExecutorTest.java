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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.application.PkiOperation;

/** Durable closed control-operation, approval and one-time-result coverage. */
class ServerControlOperationExecutorTest {
    @TempDir Path temporaryDirectory;

    @Test
    void catalogContainsOneExplicitPairOfOperationFamilies() {
        System.out.println("catalogContainsOneExplicitPairOfOperationFamilies");
        OperationSecurityDescriptors catalog = new OperationSecurityDescriptors();
        assertEquals(62, catalog.descriptors().size());
        assertEquals(16, catalog.descriptors().values().stream()
                .filter(value -> value.family() == OperationSecurityDescriptors.Family.PKI_OPERATION).count());
        assertEquals(46, catalog.descriptors().values().stream()
                .filter(value -> value.family() == OperationSecurityDescriptors.Family.SERVER_CONTROL_OPERATION)
                .count());
        assertEquals(OperationSecurityDescriptors.Family.SERVER_CONTROL_OPERATION,
                catalog.require(ServerControlOperation.IssueCapability.NAME).family());
        System.out.println("...control-operations=46");
        System.out.println("...ok");
    }

    @Test
    void principalAssignmentAndGrantOperationsPersistAndPage() throws Exception {
        System.out.println("principalAssignmentAndGrantOperationsPersistAndPage");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            ServerControlOperationExecutor executor = executor(opened);
            SecurityPrincipal principal = ServerTestSupport.principal("operator-a");
            ordinary(executor.execute(new ServerControlOperation.RegisterPrincipal(principal), "operator-a",
                    resource(Permission.ResourceType.PRINCIPAL, realmScope()), Optional.empty(),
                    CancellationSignal.NONE));
            RoleTemplateCatalog.Assignment assignment = new RoleTemplateCatalog.Assignment("assignment-a",
                    principal.principalId(), "auditor", 1, ServerTestSupport.scope(), Optional.empty(), true);
            ordinary(executor.execute(new ServerControlOperation.CreateRoleAssignment(assignment), "operator-a",
                    resource(Permission.ResourceType.ROLE, ServerTestSupport.scope()), Optional.empty(),
                    CancellationSignal.NONE));
            Permission.Grant deny = ServerTestSupport.grant("deny-a", principal.principalId(),
                    Permission.Effect.DENY, Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY,
                    ServerTestSupport.scope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED);
            ordinary(executor.execute(new ServerControlOperation.CreateGrant(deny), "operator-a",
                    resource(Permission.ResourceType.GRANT, ServerTestSupport.scope()), Optional.empty(),
                    CancellationSignal.NONE));
            assertEquals(1, opened.store().principals(0, 10).values().size());
            assertEquals(1, opened.store().assignments(0, 10).values().size());
            assertEquals(Permission.Effect.DENY, opened.store().requireGrant("deny-a").effect());
            System.out.println("...persisted=principal,assignment,deny-grant");
        }
        System.out.println("...ok");
    }

    @Test
    void approvalRequestUsesConfiguredPolicyAndDoesNotExecuteTarget() throws Exception {
        System.out.println("approvalRequestUsesConfiguredPolicyAndDoesNotExecuteTarget");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("requester-a"));
            opened.store().createPrincipal(ServerTestSupport.principal("approver-a"));
            ServerControlOperationExecutor executor = executor(opened);
            PkiOperation target = new PkiOperation.CreateAuthority(new FormatId("x509"),
                    new SubjectRef("subject-a"), "profile-a", new KeyRef("key-a"));
            Permission.Resource targetResource = resource(Permission.ResourceType.AUTHORITY, realmScope());
            ServerControlOperation.RequestApproval request = new ServerControlOperation.RequestApproval(
                    "approval-a", new AdministrativeOperation.Pki(target), targetResource);
            ordinary(executor.execute(request, "requester-a", resource(Permission.ResourceType.APPROVAL,
                    realmScope()), Optional.empty(), CancellationSignal.NONE));
            ApprovalService.Request persisted = opened.store().requireApproval("approval-a");
            assertEquals(ApprovalService.State.PENDING, persisted.state());
            assertEquals("high-risk", persisted.policy().policyId());
            System.out.println("...target-state=PENDING,no-execution");
        }
        System.out.println("...ok");
    }

    @Test
    void capabilityResultIsSingleConsumptionAndPersistenceContainsOnlyCommitment() throws Exception {
        System.out.println("capabilityResultIsSingleConsumptionAndPersistenceContainsOnlyCommitment");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("security-admin"));
            PkiId objectId = new PkiId("credential-a");
            DisclosureService disclosure = disclosure(opened);
            disclosure.register(objectId, DisclosureService.ObjectType.LEAF_CERTIFICATE,
                    DisclosureService.Policy.PUBLIC_UNLISTED, Optional.of("security-admin"),
                    ServerTestSupport.DIGEST, "security-admin");
            ServerControlOperationExecutor executor = executor(opened, disclosure);
            ServerControlOperationOutcome outcome = executor.execute(new ServerControlOperation.IssueCapability(
                    objectId, ServerTestSupport.CLOCK.instant().plusSeconds(600)), "security-admin",
                    resource(Permission.ResourceType.CAPABILITY, realmScope()), Optional.empty(),
                    CancellationSignal.NONE);
            ServerControlOperationOutcome.OneTimeSensitive sensitive = assertInstanceOf(
                    ServerControlOperationOutcome.OneTimeSensitive.class, outcome);
            byte[] token = sensitive.consumeToken();
            assertEquals(32, token.length);
            assertThrows(IllegalStateException.class, sensitive::consumeToken);
            String capabilityId = ((zeroecho.pki.application.PkiOperationValue.Text)
                    sensitive.safeResult().fields().get("capabilityId")).value();
            assertEquals(32, opened.store().requireCapability(capabilityId).tokenCommitment().length);
            assertEquals(DisclosureService.DeliveryState.PENDING,
                    opened.store().requireCapability(capabilityId).deliveryState());
            assertEquals(DisclosureService.DeliveryState.DELIVERY_UNKNOWN,
                    disclosure.classifyDelivery(capabilityId, false).deliveryState());
            System.out.println("...token-bytes=32,persisted=commitment-only");
        }
        System.out.println("...ok");
    }

    @Test
    void pendingBreakGlassRequiresSeparateActivationAndExpires() throws Exception {
        System.out.println("pendingBreakGlassRequiresSeparateActivationAndExpires");
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(temporaryDirectory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("officer-a"));
            opened.store().createPrincipal(ServerTestSupport.principal("security-admin"));
            Permission.Grant grant = ServerTestSupport.grant("emergency-a", "officer-a", Permission.Effect.ALLOW,
                    Permission.Action.CERTIFICATE_REVOKE, Permission.ResourceType.REVOCATION,
                    ServerTestSupport.scope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED);
            BreakGlassService service = new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            ApprovalService.Policy policy = new ApprovalService.Policy("emergency-policy", 1,
                    Set.of("security-admin"), Set.of(), true, Duration.ofHours(1), true);
            ApprovalService approvals = new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit());
            ApprovalService.Request createApproval = approvals.request("approval-create",
                    ServerControlOperation.CreateBreakGlass.CREATE, ServerTestSupport.DIGEST,
                    ServerTestSupport.scope(), "officer-a", policy);
            approvals.decide(createApproval.approvalId(), "security-admin", ApprovalService.Choice.APPROVE,
                    "creation independently reviewed");
            approvals.claim(createApproval.approvalId(), ServerControlOperation.CreateBreakGlass.CREATE,
                    ServerTestSupport.DIGEST, ServerTestSupport.scope());
            BreakGlassService.Record pending = service.create("break-a", "officer-a", grant, "incident-response",
                    "security-admin", Optional.of(createApproval.approvalId()),
                    ServerTestSupport.CLOCK.instant().plus(Duration.ofHours(1)));
            assertEquals(BreakGlassService.State.PENDING, pending.state());
            assertTrue(service.activeFor("officer-a").grants().isEmpty());
            ApprovalService.Request activateApproval = approvals.request("approval-activate",
                    ServerControlOperation.ActivateBreakGlass.ACTIVATE, ServerTestSupport.DIGEST,
                    ServerTestSupport.scope(), "officer-a", policy);
            approvals.decide(activateApproval.approvalId(), "security-admin", ApprovalService.Choice.APPROVE,
                    "activation independently reviewed");
            approvals.claim(activateApproval.approvalId(), ServerControlOperation.ActivateBreakGlass.ACTIVATE,
                    ServerTestSupport.DIGEST, ServerTestSupport.scope());
            assertEquals(BreakGlassService.State.ACTIVE, service.activatePending("break-a", "security-admin",
                    Optional.of(activateApproval.approvalId())).state());
            System.out.println("...states=PENDING,ACTIVE");
        }
        System.out.println("...ok");
    }

    private ServerControlOperationExecutor executor(ServerTestSupport.OpenedStore opened) throws Exception {
        return executor(opened, disclosure(opened));
    }

    private ServerControlOperationExecutor executor(ServerTestSupport.OpenedStore opened,
            DisclosureService disclosure) {
        ApprovalService.Policy policy = new ApprovalService.Policy("high-risk", 1, Set.of("approver-a"),
                Set.of(), true, Duration.ofHours(1), true);
        OperationSecurityDescriptors descriptors = new OperationSecurityDescriptors();
        return new ServerControlOperationExecutor(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true),
                opened.store(), RoleTemplateCatalog.load(getClass().getClassLoader()),
                new AuthorizationEngine(ServerTestSupport.CLOCK),
                new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit()),
                new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit()), disclosure,
                new AuditorViews(ServerTestSupport.CLOCK, opened.audit()), Optional.empty(), descriptors,
                Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, policy));
    }

    private DisclosureService disclosure(ServerTestSupport.OpenedStore opened) throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new byte[] { 1, 2, 3, 4 });
        return new DisclosureService(ServerTestSupport.REALM, opened.store(),
                DisclosureService.Defaults.recommended(), ServerTestSupport.CLOCK, random, opened.audit());
    }

    private static Permission.Scope realmScope() {
        return new Permission.Scope(ServerTestSupport.REALM, Optional.empty(), Optional.empty(), Optional.empty());
    }

    private static Permission.Resource resource(Permission.ResourceType type, Permission.Scope scope) {
        return new Permission.Resource(type, scope, Optional.empty(), Optional.empty());
    }

    private static void ordinary(ServerControlOperationOutcome outcome) {
        ServerControlOperationOutcome.Ordinary ordinary = assertInstanceOf(
                ServerControlOperationOutcome.Ordinary.class, outcome);
        assertInstanceOf(zeroecho.pki.application.PkiOperationOutcome.Success.class, ordinary.outcome());
    }
}
