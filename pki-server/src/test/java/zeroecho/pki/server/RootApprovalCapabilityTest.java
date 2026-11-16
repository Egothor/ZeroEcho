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

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;

/**
 * Checks explicit root-approval capability selection independently of ordinary administrative privileges.
 */
class RootApprovalCapabilityTest {
    /**
     * JUnit-managed isolated filesystem root, removed according to the configured cleanup policy.
     */
    @TempDir Path directory;

    /**
     * Checks deny, expiry, disabled state, foreign scope and unmet conditions all constrain explicit own-decision capability.
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void explicitDenyExpiredDisabledWrongScopeAndConditionalGrantsBlockOwnDecision() throws Exception {
        for (String mode : List.of("deny", "expired", "disabled", "scope", "condition", "principal")) {
            var configuration = PkiAdminBootstrapTest.configuration(directory.resolve(mode));
            PkiAdminBootstrap.bootstrap(configuration, "administrator", "approver", "trusted-proxy");
            try (var metadata = DurableTransactionalMetadataStore.open(configuration.realm().controlLogPath(), OptionalLong.of(1048576));
                    var store = new ServerControlStore(metadata)) {
                var own = store.requireGrant("bootstrap.admin.approval-own");
                if (mode.equals("principal")) {
                    var principal = store.requirePrincipal("administrator");
                    store.replacePrincipal(principal, new SecurityPrincipal(principal.principalId(), principal.type(), principal.displayName(),
                            principal.organization(), principal.attributes(), false));
                } else if (mode.equals("deny")) {
                    store.createGrant(new Permission.Grant("explicit-own-deny", own.principalId(), Permission.Effect.DENY,
                            own.action(), own.resourceType(), own.scope(), own.relationship(), own.dataView(), Set.of(), Optional.empty(), true));
                } else {
                    var scope = mode.equals("scope") ? new Permission.Scope(own.scope().realmId(),
                            Optional.of(new zeroecho.pki.api.PkiId("other-authority")), Optional.empty(), Optional.empty()) : own.scope();
                    store.replaceGrant(own, new Permission.Grant(own.grantId(), own.principalId(), own.effect(), own.action(),
                            own.resourceType(), scope, own.relationship(), own.dataView(),
                            mode.equals("condition") ? Set.of(Permission.Condition.APPROVAL_REQUIRED) : Set.of(),
                            mode.equals("expired") ? Optional.of(Instant.now().minusSeconds(60)) : Optional.empty(), !mode.equals("disabled")));
                }
            }
            try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
                var policy = configuration.realm().approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK);
                var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
                context.approvals().request("own-" + mode, "security.grant.create", "a".repeat(64), scope, "administrator", policy);
                assertThrows(IllegalStateException.class, () -> context.approvals().decide("own-" + mode,
                        "administrator", ApprovalService.Choice.APPROVE, "Root remains bounded: " + mode));
            }
        }
    }

    /**
     * Checks embedded approval service construction does not activate runtime own-decision authority merely because a capability is stored.
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void embeddedConstructorRemainsSeparatedEvenWithStoredOwnCapability() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        PkiAdminBootstrap.bootstrap(configuration, "administrator", "approver", "trusted-proxy");
        try (var metadata = DurableTransactionalMetadataStore.open(configuration.realm().controlLogPath(), OptionalLong.of(1048576));
                var store = new ServerControlStore(metadata); var audit = PkiBootstrap.openAudit(configuration.realm().pkiSessionConfiguration().audit())) {
            var service = new ApprovalService(store, Clock.systemUTC(), audit);
            var policy = configuration.realm().approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK);
            var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            service.request("embedded-own", "security.grant.create", "b".repeat(64), scope, "administrator", policy);
            assertThrows(IllegalStateException.class, () -> service.decide("embedded-own", "administrator",
                    ApprovalService.Choice.APPROVE, "No runtime authorizer installed"));
        }
    }

    /**
     * Checks own-decision privilege cannot replace the ordinary permission needed to approve the target.
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void ownPrivilegeDoesNotReplaceOrdinaryApprovalPermission() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        PkiAdminBootstrap.bootstrap(configuration, "administrator", "approver", "trusted-proxy");
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            context.grant(new Permission.Grant("ordinary-approve-deny", "administrator", Permission.Effect.DENY,
                    Permission.Action.REQUEST_APPROVE, Permission.ResourceType.APPROVAL, scope, Permission.Relationship.ANY,
                    Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(), true), "system");
            var resource = new Permission.Resource(Permission.ResourceType.APPROVAL, scope, Optional.empty(), Optional.of("administrator"));
            assertFalse(context.gateway().authorizeControl("administrator", Permission.Action.REQUEST_APPROVE,
                    resource, Permission.Context.empty(), "root-still-needs-base-permission").allowed());
        }
    }

    /**
     * Checks root contributes only one eligible threshold decision and cannot duplicate its vote or ignore eligibility.
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void rootStillNeedsEligibilityAndDistinctThresholdDecisions() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        PkiAdminBootstrap.bootstrap(configuration, "administrator", "approver", "trusted-proxy");
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            var threshold = new ApprovalService.Policy("two-of-two", 2, Set.of("administrator", "approver"), Set.of(),
                    true, java.time.Duration.ofHours(1), true);
            context.approvals().request("threshold-root", "security.grant.create", "c".repeat(64), scope, "administrator", threshold);
            assertEquals(ApprovalService.State.PENDING, context.approvals().decide("threshold-root", "administrator",
                    ApprovalService.Choice.APPROVE, "Root contributes one decision").state());
            assertThrows(IllegalStateException.class, () -> context.approvals().decide("threshold-root", "administrator",
                    ApprovalService.Choice.APPROVE, "No duplicate count"));
            assertEquals(ApprovalService.State.APPROVED, context.approvals().decide("threshold-root", "approver",
                    ApprovalService.Choice.APPROVE, "Second distinct decision").state());
            var ineligible = new ApprovalService.Policy("only-ordinary", 1, Set.of("approver"), Set.of(),
                    true, java.time.Duration.ofHours(1), true);
            context.approvals().request("ineligible-root", "security.grant.create", "d".repeat(64), scope, "administrator", ineligible);
            assertThrows(IllegalStateException.class, () -> context.approvals().decide("ineligible-root", "administrator",
                    ApprovalService.Choice.APPROVE, "Root is not eligible"));
        }
    }

    /**
     * Checks a principal named root receives no implicit ability to decide its own request.
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void rootNameAloneDoesNotConferOwnDecisionCapability() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        PkiAdminBootstrap.bootstrap(configuration, "administrator", "approver", "trusted-proxy");
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            context.createPrincipal(new SecurityPrincipal("root", SecurityPrincipal.Type.USER, "root", Optional.empty(), Map.of(), true), "system");
            var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            var policy = new ApprovalService.Policy("root-named-user", 1, Set.of("root"), Set.of(), true,
                    java.time.Duration.ofHours(1), true);
            context.approvals().request("root-name-alone", "security.grant.create", "e".repeat(64), scope, "root", policy);
            assertThrows(IllegalStateException.class, () -> context.approvals().decide("root-name-alone", "root",
                    ApprovalService.Choice.APPROVE, "Name alone grants nothing"));
        }
    }

    /**
     * Checks own-decision capability retains persistence code 10 and is absent from every implicit built-in role action set.
     */
    @Test
    void rootCapabilityHasStableCodeAndNoBuiltInRoleImplicitlyIncludesIt() {
        assertEquals(10, Permission.Action.APPROVAL_DECIDE_OWN.code());
        assertEquals(Permission.Action.APPROVAL_DECIDE_OWN, Permission.Action.fromCode(10));
        assertTrue(RoleTemplateCatalog.load(getClass().getClassLoader()).templates().stream()
                .noneMatch(template -> template.actions().contains(Permission.Action.APPROVAL_DECIDE_OWN)));
    }
}
