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
import java.time.Duration;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.impl.fs.DurableTransactionalMetadataStore;

class PkiAdminBootstrapTest {
    @TempDir Path directory;

    @Test
    void onlyDesignatedRootCanDecideOwnRequestWhilePolicyRemainsSeparated() throws Exception {
        var configuration = configuration();
        PkiAdminBootstrap.bootstrap(configuration, "administrator", "approver", "trusted-proxy");
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            var policy = configuration.realm().approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK);
            assertTrue(policy.requesterSeparation());
            var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            context.approvals().request("root-own", "security.grant.create", "a".repeat(64), scope, "administrator", policy);
            assertEquals(ApprovalService.State.APPROVED, context.approvals().decide("root-own", "administrator",
                    ApprovalService.Choice.APPROVE, "Explicit root decision").state());
            context.approvals().request("ordinary-own", "security.grant.create", "b".repeat(64), scope, "approver", policy);
            assertThrows(IllegalStateException.class, () -> context.approvals().decide("ordinary-own", "approver",
                    ApprovalService.Choice.APPROVE, "Own ordinary request"));
            assertEquals(ApprovalService.State.APPROVED, context.approvals().decide("ordinary-own", "administrator",
                    ApprovalService.Choice.APPROVE, "Independent decision").state());
        }
    }

    @Test
    void initialUsersCanInspectRealmButProxyCannot() throws Exception {
        var configuration = configuration();
        PkiAdminBootstrap.bootstrap(configuration, "administrator", "approver", "trusted-proxy");
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            var resource = new Permission.Resource(Permission.ResourceType.REALM,
                    new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty()),
                    Optional.empty(), Optional.empty());
            for (String principal : List.of("administrator", "approver")) {
                assertTrue(context.gateway().authorizeControl(principal, Permission.Action.REALM_READ,
                        resource, Permission.Context.empty(), "bootstrap-realm-regression").allowed());
            }
            assertFalse(context.gateway().authorizeControl("trusted-proxy", Permission.Action.REALM_READ,
                    resource, Permission.Context.empty(), "bootstrap-proxy-regression").allowed());
        }
    }

    @Test
    void createsPersistedAdministratorsAndOnlyForwardPermissionForProxy() throws Exception {
        var configuration = configuration();
        PkiAdminBootstrap.bootstrap(configuration, "administrator", "approver", "trusted-proxy");
        try (var metadata = DurableTransactionalMetadataStore.open(configuration.realm().controlLogPath(),
                OptionalLong.of(1_048_576)); var control = new ServerControlStore(metadata)) {
            assertEquals(SecurityPrincipal.Type.USER, control.requirePrincipal("administrator").type());
            assertEquals(SecurityPrincipal.Type.USER, control.requirePrincipal("approver").type());
            assertEquals(SecurityPrincipal.Type.SERVICE, control.requirePrincipal("trusted-proxy").type());
            var proxyGrants = control.grantsFor("trusted-proxy");
            assertEquals(1, proxyGrants.size());
            assertEquals(Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY, proxyGrants.getFirst().action());
            var descriptors = new OperationSecurityDescriptors().descriptors();
            for (String principal : List.of("administrator", "approver")) {
                // The mandatory inventory aliases search authority; the three content grants have stable additive IDs.
                assertEquals(descriptors.size() - 1 + 3 + (principal.equals("administrator") ? 2 : 1), control.grantsFor(principal).size());
                for(Permission.Action action:List.of(Permission.Action.CERTIFICATE_READ_CONTENT,Permission.Action.CERTIFICATE_DOWNLOAD)) {
                    assertTrue(control.grantsFor(principal).stream().anyMatch(value -> value.action()==action
                            &&value.dataView()==Permission.DataView.CONTENT_FULL&&value.enabled()));
                }
                assertTrue(control.grantsFor(principal).stream().anyMatch(value -> value.action()==Permission.Action.CRL_DOWNLOAD
                        &&value.resourceType()==Permission.ResourceType.STATUS_OBJECT&&value.dataView()==Permission.DataView.CONTENT_FULL&&value.enabled()));
                for (var descriptor : descriptors.values()) {
                    assertTrue(control.grantsFor(principal).stream().anyMatch(grant ->
                            grant.action() == descriptor.action() && grant.resourceType() == descriptor.resourceType()
                            && grant.dataView() == descriptor.dataView() && grant.enabled()
                            && grant.scope().realmId().equals(configuration.realm().realmId())
                            && grant.scope().authorityId().isEmpty()));
                }
            }
        }
        try (var context = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            assertTrue(context.principal("administrator").enabled());
            assertTrue(context.principal("approver").enabled());
        }
        byte[] original = Files.readAllBytes(configuration.realm().controlLogPath());
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.bootstrap(configuration,
                "administrator", "approver", "trusted-proxy"));
        assertArrayEquals(original, Files.readAllBytes(configuration.realm().controlLogPath()));
    }

    @Test
    void rejectsMismatchedIdentityAndDuplicateIdentityBeforeStateCreation() throws Exception {
        var configuration = configuration();
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.bootstrap(configuration,
                "missing", "approver", "trusted-proxy"));
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.bootstrap(configuration,
                "administrator", "administrator", "trusted-proxy"));
        assertFalse(Files.exists(configuration.realm().controlLogPath()));
    }

    @Test
    void refusesExistingEmptyControlLogAndExistingPkiState() throws Exception {
        var configuration = configuration();
        Files.createFile(configuration.realm().controlLogPath());
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.bootstrap(configuration,
                "administrator", "approver", "trusted-proxy"));
        Files.delete(configuration.realm().controlLogPath());
        Path store = Path.of(configuration.realm().pkiSessionConfiguration().store().require("root"));
        Files.createDirectories(store);
        Files.writeString(store.resolve("existing"), "existing");
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.bootstrap(configuration,
                "administrator", "approver", "trusted-proxy"));
    }

    @Test
    void retainsReservationAndRefusesPartialBootstrapRetry() throws Exception {
        var configuration = configuration();
        Path control = configuration.realm().controlLogPath();
        Files.createFile(control.resolveSibling(control.getFileName() + ".admin-bootstrap-started"));
        assertThrows(java.nio.file.FileAlreadyExistsException.class, () -> PkiAdminBootstrap.bootstrap(configuration,
                "administrator", "approver", "trusted-proxy"));
        assertFalse(Files.exists(control));
    }

    @Test
    void rejectsSameCertificateForAdminAndApprover() throws Exception {
        var source = configuration();
        var auth = source.authentication();
        var duplicate = new PkiServerConfiguration.Authentication(auth.mode(), List.of(), auth.proxyTransportMappings(),
                List.of(mapping("admin", "administrator", "a"), mapping("approver", "approver", "a")),
                auth.trustedProxyPrincipalIds(), auth.forwardedCertificateFormat(), auth.forwardedCertificateHeaderName(),
                auth.forwardedCertificateChainHeaderName(), auth.administrativeClientTrust(),
                auth.maximumForwardedCertificateBytes(), auth.maximumForwardedChainBytes());
        var configuration = withAuthentication(source, duplicate);
        assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.bootstrap(configuration,
                "administrator", "approver", "trusted-proxy"));
        assertFalse(Files.exists(configuration.realm().controlLogPath()));
    }

    @Test
    void cliRejectsUnknownAndRepeatedOptionsAndOffersHelp() {
        assertEquals(0, PkiAdminBootstrap.run(new String[] {"--help"}));
        assertEquals(2, PkiAdminBootstrap.run(new String[] {}));
        assertEquals(2, PkiAdminBootstrap.run(new String[] {"--config", "x", "--admin-id", "a", "--approver-id", "b", "--wat", "c"}));
        assertEquals(2, PkiAdminBootstrap.run(new String[] {"--config", "x", "--admin-id", "a", "--approver-id", "b", "--config", "c"}));
    }

    private PkiServerConfiguration configuration() throws Exception { return configuration(directory); }

    static PkiServerConfiguration configuration(Path directory) throws Exception {
        var tls = HttpServerTestSupport.tls();
        var source = HttpServerTestSupport.proxyConfiguration(directory, tls, ForwardedCertificateFormat.RFC9440);
        var auth = source.authentication();
        var authentication = new PkiServerConfiguration.Authentication(auth.mode(), List.of(),
                List.of(mapping("proxy", "trusted-proxy", "c")),
                List.of(mapping("admin", "administrator", "a"), mapping("approver", "approver", "b")),
                Set.of("trusted-proxy"), auth.forwardedCertificateFormat(), auth.forwardedCertificateHeaderName(),
                auth.forwardedCertificateChainHeaderName(), auth.administrativeClientTrust(),
                auth.maximumForwardedCertificateBytes(), auth.maximumForwardedChainBytes());
        var realm = source.realm();
        var current = realm.approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK);
        var policy = new ApprovalService.Policy(current.policyId(), 1, Set.of("administrator", "approver"),
                Set.of(), true, Duration.ofHours(1), true);
        var policies = Map.of(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, policy);
        var configured = new ServerRealmConfiguration(realm.realmId(), realm.displayName(), realm.confirmationProofPolicy(),
                realm.pkiSessionConfiguration(), realm.authorityExposure(), realm.authorizationCommitment(), policy.commitment(),
                ServerRealmConfiguration.extendedApprovalCommitment(policies), realm.disclosureCommitment(), realm.disclosureDefaults(),
                realm.controlLogPath(), realm.controlStoreId(), policies);
        return withAuthentication(new PkiServerConfiguration(source.version(), source.serverName(), configured, source.listener(),
                source.authentication(), source.execution(), source.runtime()), authentication);
    }

    private static PkiServerConfiguration withAuthentication(PkiServerConfiguration source,
            PkiServerConfiguration.Authentication authentication) {
        return new PkiServerConfiguration(source.version(), source.serverName(), source.realm(), source.listener(),
                authentication, source.execution(), source.runtime());
    }

    private static PkiServerConfiguration.ClientCertificateMapping mapping(String id, String principal, String digit) {
        return new PkiServerConfiguration.ClientCertificateMapping(id, principal, Optional.of(digit.repeat(64)),
                Optional.empty(), Optional.empty());
    }
}
