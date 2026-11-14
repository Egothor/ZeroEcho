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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;

class PkiRootAdminTest {
    @TempDir Path directory;

    @Test
    void explicitDesignationAddsOnlyRootCapabilityAndIsIdempotent() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        legacy(configuration);
        var before = snapshot(configuration);
        PkiAdminBootstrap.provisionRootAdmin(configuration, "administrator", "approver", "trusted-proxy");
        var after = snapshot(configuration);
        assertEquals(before.get("administrator").size() + 1, after.get("administrator").size());
        assertTrue(after.get("administrator").containsAll(before.get("administrator")));
        assertEquals(before.get("approver"), after.get("approver"));
        assertEquals(before.get("trusted-proxy"), after.get("trusted-proxy"));
        PkiAdminBootstrap.provisionRootAdmin(configuration, "administrator", "approver", "trusted-proxy");
        assertEquals(after, snapshot(configuration));
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            assertTrue(context.configuration().approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK).requesterSeparation());
        }
    }

    @Test
    void designationAuthorizesExistingOwnPendingRequestWithoutChangingItsPolicySnapshot() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        legacy(configuration);
        ApprovalService.Policy policy = configuration.realm().approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK);
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            context.approvals().request("legacy-pending", "security.grant.create", "a".repeat(64), scope, "administrator", policy);
            assertThrows(IllegalStateException.class, () -> context.approvals().decide("legacy-pending", "administrator",
                    ApprovalService.Choice.APPROVE, "No own capability yet"));
        }
        PkiAdminBootstrap.provisionRootAdmin(configuration, "administrator", "approver", "trusted-proxy");
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            var request = context.approvals().requireCurrent("legacy-pending");
            assertEquals(policy, request.policy());
            assertTrue(request.policy().requesterSeparation());
            assertEquals(ApprovalService.State.APPROVED, context.approvals().decide("legacy-pending", "administrator",
                    ApprovalService.Choice.APPROVE, "Explicit current root capability").state());
        }
    }

    @Test
    void designationRefusesDisabledInitialUserOrRevokedBaselineGrant() throws Exception {
        for (String kind : List.of("disabled", "revoked")) {
            var configuration = PkiAdminBootstrapTest.configuration(directory.resolve(kind));
            legacy(configuration);
            if (kind.equals("disabled")) {
                try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
                    context.setPrincipalEnabled("administrator", false, "system");
                }
            } else {
                try (var metadata = DurableTransactionalMetadataStore.open(configuration.realm().controlLogPath(), OptionalLong.of(1048576));
                        var store = new ServerControlStore(metadata)) {
                    var value = store.requireGrant("bootstrap.admin.0");
                    store.replaceGrant(value, new Permission.Grant(value.grantId(), value.principalId(), value.effect(), value.action(),
                            value.resourceType(), value.scope(), value.relationship(), value.dataView(), value.conditions(), value.expiresAt(), false));
                }
            }
            var before = snapshot(configuration);
            assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.provisionRootAdmin(configuration,
                    "administrator", "approver", "trusted-proxy"));
            assertEquals(before, snapshot(configuration));
        }
    }

    @Test
    void uninitializedPkiDirectoryIsNotInitializedDuringDesignation() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        legacy(configuration);
        Path root = Path.of(configuration.realm().pkiSessionConfiguration().store().require("root"));
        Files.move(root, root.resolveSibling(root.getFileName() + "-retained"));
        Files.createDirectory(root);
        var before = snapshot(configuration);
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.provisionRootAdmin(configuration,
                "administrator", "approver", "trusted-proxy"));
        assertFalse(Files.exists(root.resolve("VERSION")));
        assertEquals(before, snapshot(configuration));
    }

    @Test
    void missingPkiRootIsNotReinitializedDuringDesignation() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        legacy(configuration);
        Path root = Path.of(configuration.realm().pkiSessionConfiguration().store().require("root"));
        Files.move(root, root.resolveSibling(root.getFileName() + "-retained"));
        var before = snapshot(configuration);
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.provisionRootAdmin(configuration,
                "administrator", "approver", "trusted-proxy"));
        assertFalse(Files.exists(root));
        assertEquals(before, snapshot(configuration));
    }

    @Test
    void missingStateAndArbitraryIdentityCannotBecomeRoot() throws Exception {
        var configuration = PkiAdminBootstrapTest.configuration(directory);
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.provisionRootAdmin(configuration,
                "administrator", "approver", "trusted-proxy"));
        assertFalse(Files.exists(configuration.realm().controlLogPath()));
        legacy(configuration);
        var before = snapshot(configuration);
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.provisionRootAdmin(configuration,
                "approver", "administrator", "trusted-proxy"));
        assertEquals(before, snapshot(configuration));
        assertEquals(2, PkiRootAdmin.run(new String[] {"--unknown", "value"}));
    }

    private static Map<String, List<Permission.Grant>> snapshot(PkiServerConfiguration configuration) throws Exception {
        try (var metadata = DurableTransactionalMetadataStore.open(configuration.realm().controlLogPath(), OptionalLong.of(1048576));
                var store = new ServerControlStore(metadata)) {
            return Map.of("administrator", store.grantsFor("administrator"), "approver", store.grantsFor("approver"),
                    "trusted-proxy", store.grantsFor("trusted-proxy"));
        }
    }

    private static void legacy(PkiServerConfiguration configuration) throws Exception {
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            context.createPrincipal(new SecurityPrincipal("trusted-proxy", SecurityPrincipal.Type.SERVICE,
                    "Initial reverse proxy", Optional.empty(), Map.of(), true), "system");
            context.grant(new Permission.Grant("bootstrap.proxy-forward", "trusted-proxy", Permission.Effect.ALLOW,
                    Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY, Permission.ResourceType.REALM, scope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(), true), "system");
            var historical = new OperationSecurityDescriptors().descriptors().values().stream()
                    .filter(descriptor -> !descriptor.operationId().equals(ServerControlOperation.GenerateManagedKey.NAME))
                    .filter(descriptor -> !descriptor.operationId().equals(zeroecho.pki.application.PkiOperation.ListCredentials.NAME))
                    .sorted(java.util.Comparator.comparing(OperationSecurityDescriptors.Descriptor::operationId)).toList();
            assertEquals(150, historical.size());
            assertEquals("acme.account.deactivate", historical.get(0).operationId());
            assertEquals("credential.issue", historical.get(43).operationId());
            assertEquals("credential.reissue", historical.get(44).operationId());
            assertEquals("credential.renew", historical.get(45).operationId());
            assertEquals("credential.replace", historical.get(46).operationId());
            assertEquals("status.schedule.set", historical.get(149).operationId());
            for (String principal : List.of("administrator", "approver")) {
                context.createPrincipal(new SecurityPrincipal(principal, SecurityPrincipal.Type.USER, principal, Optional.empty(), Map.of(), true), "system");
                String prefix = principal.equals("administrator") ? "bootstrap.admin." : "bootstrap.approver.";
                int index = 0;
                for (var descriptor : historical) {
                    context.grant(new Permission.Grant(prefix + index++, principal, Permission.Effect.ALLOW, descriptor.action(),
                            descriptor.resourceType(), scope, Permission.Relationship.ANY, descriptor.dataView(), Set.of(), Optional.empty(), true), "system");
                }
                context.grant(new Permission.Grant(prefix + "realm-read", principal, Permission.Effect.ALLOW, Permission.Action.REALM_READ,
                        Permission.ResourceType.REALM, scope, Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED, Set.of(), Optional.empty(), true), "system");
            }
        }
        Files.createFile(configuration.realm().controlLogPath().resolveSibling(configuration.realm().controlLogPath().getFileName() + ".admin-bootstrap-started"));
    }
}
