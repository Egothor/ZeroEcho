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
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.server.http.HttpOperationCodec;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.ManagedKeyGeneration;

class ManagedKeyGenerationIntegrationTest {
    @Test void firstAdministratorGeneratesButOrdinaryAdministratorUsesTheKeyForAnActualCa(@TempDir Path root) throws Exception {
        var configuration = configuration(root);
        PkiAdminBootstrap.bootstrap(withoutSigning(configuration), "administrator", "approver", "trusted-proxy");
        try (var context = ServerRealmContext.open(configuration.realm(), dependencies())) {
            var decoded = HttpOperationCodec.decode("key.generate",
                    "{\"version\":1,\"arguments\":{\"generationId\":\"new-ca-key\",\"parameters\":\"RSA_4096\"}}".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    4096, configuration.realm().realmId(), new OperationSecurityDescriptors()::require);
            var operation = assertInstanceOf(ServerControlOperation.GenerateManagedKey.class,
                    assertInstanceOf(AdministrativeOperation.Control.class, decoded.operation()).operation());
            var scope = new Permission.Scope(configuration.realm().realmId(), Optional.empty(), Optional.empty(), Optional.empty());
            var keyResource = new Permission.Resource(Permission.ResourceType.MANAGED_KEY, scope, Optional.empty(), Optional.empty());
            // Even a broad grant and own-approval capability cannot turn another administrator into the first administrator.
            context.grant(ServerTestSupport.grant("ordinary-keygen", "approver", Permission.Effect.ALLOW,
                    Permission.Action.MANAGED_KEY_GENERATE, Permission.ResourceType.MANAGED_KEY, scope,
                    Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED), "administrator");
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, context.gateway().execute(
                    request(context, "approver", new AdministrativeOperation.Control(operation), keyResource, Optional.empty()), CancellationSignal.NONE));
            var generated = assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class,
                    approved(context, "administrator", new AdministrativeOperation.Control(operation), keyResource, "generate-approval"));
            var completed = assertInstanceOf(PkiOperationOutcome.Completed.class,
                    assertInstanceOf(ServerControlOperationOutcome.Ordinary.class, generated.outcome()).outcome());
            var value = assertInstanceOf(PkiOperationValue.ObjectValue.class, completed.result().fields().get("value"));
            KeyRef key = new KeyRef(assertInstanceOf(PkiOperationValue.Text.class, value.fields().get("keyRef")).value());
            assertEquals(java.util.Set.of("generationId", "keyRef", "parameters", "subjectPublicKeyInfo"), value.fields().keySet());
            byte[] encoded = zeroecho.pki.server.http.StrictJson.encode(value);
            assertInstanceOf(PkiOperationValue.ObjectValue.class, zeroecho.pki.server.http.StrictJson.parse(encoded, 32768));
            assertFalse(new String(encoded, java.nio.charset.StandardCharsets.UTF_8).contains("PRIVATE KEY"));
            assertTrue(context.session().managedKeyGeneration().isPresent());
            for (var template : BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())) {
                if (template.definition().profileId().equals("root-ca")) {
                    context.session().profiles().importBuiltIn(template);
                    context.session().profiles().activateProfile("root-ca", template.definition().profileVersion());
                }
            }
            var ca = new PkiSigningOperation.CreateAuthority(new FormatId("x509"), new SubjectRef("CN=Generated Key Root"), "root-ca", key);
            var authority = new Permission.Resource(Permission.ResourceType.AUTHORITY, scope, Optional.empty(), Optional.empty());
            var issued = assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                    approved(context, "approver", new AdministrativeOperation.Signing(ca), authority, "create-ca-approval"));
            if (issued.outcome() instanceof PkiOperationOutcome.Pending pending) {
                long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
                var semantic = context.session().semanticSigning().orElseThrow();
                while (System.nanoTime() < deadline && semantic.find(pending.operationId()).orElseThrow().state() != SemanticSigningState.COMPLETED) {
                    Thread.onSpinWait();
                }
                assertEquals(SemanticSigningState.COMPLETED, semantic.find(pending.operationId()).orElseThrow().state());
            } else {
                assertInstanceOf(PkiOperationOutcome.Completed.class, issued.outcome());
            }
            assertEquals(1, context.session().repository().authorities(Optional.empty(), 10).size());
        }
    }

    @Test void codecUsesClosedExplicitParametersAndLegacyConfigurationDisablesGeneration(@TempDir Path root) throws Exception {
        var source = PkiAdminBootstrapTest.configuration(root);
        assertTrue(source.realm().initialAdministratorPrincipalId().isEmpty());
        var descriptors = new OperationSecurityDescriptors();
        var decoded = HttpOperationCodec.decode("key.generate", "{\"version\":1,\"arguments\":{\"generationId\":\"example\",\"parameters\":\"ECDSA_P384\"}}".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                4096, source.realm().realmId(), descriptors::require);
        assertInstanceOf(ServerControlOperation.GenerateManagedKey.class,
                assertInstanceOf(AdministrativeOperation.Control.class, decoded.operation()).operation());
        assertThrows(IllegalArgumentException.class, () -> HttpOperationCodec.decode("key.generate",
                "{\"version\":1,\"arguments\":{\"generationId\":\"example\",\"parameters\":\"DEFAULT\"}}".getBytes(java.nio.charset.StandardCharsets.UTF_8),
                4096, source.realm().realmId(), descriptors::require));
    }

    private static ServerOperationGateway.Outcome approved(ServerRealmContext context, String actor,
            AdministrativeOperation operation, Permission.Resource resource, String approvalId) {
        String commitment = assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,
                context.gateway().execute(request(context, actor, operation, resource, Optional.empty()), CancellationSignal.NONE)).operationCommitment();
        var policy = context.configuration().approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK);
        context.approvals().request(approvalId, operation.name(), commitment, resource.scope(), actor, policy);
        context.approvals().decide(approvalId, "administrator", ApprovalService.Choice.APPROVE, "Explicit integration-test approval");
        return context.gateway().execute(request(context, actor, operation, resource, Optional.of(approvalId)), CancellationSignal.NONE);
    }

    private static ServerOperationGateway.Request request(ServerRealmContext context, String actor,
            AdministrativeOperation operation, Permission.Resource resource, Optional<String> approval) {
        return new ServerOperationGateway.Request(context.configuration().realmId(), actor, operation, resource,
                Permission.Relationship.ANY, Permission.Context.empty(), approval, "managed-key-test");
    }

    private static PkiSessionRuntimeDependencies dependencies() {
        return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(() -> new KeyringPassword("integration-test-key".toCharArray()));
    }

    static PkiServerConfiguration withoutSigning(PkiServerConfiguration source) {
        var realm = source.realm(); var session = realm.pkiSessionConfiguration();
        var bootstrap = new PkiSessionConfiguration(session.version(), session.store(), session.audit(), Optional.empty(), session.publishers(), session.bindingProviders());
        var configured = new ServerRealmConfiguration(realm.realmId(), realm.displayName(), realm.confirmationProofPolicy(), bootstrap,
                realm.authorityExposure(), realm.authorizationCommitment(), realm.approvalCommitment(), realm.extendedApprovalCommitment(),
                realm.disclosureCommitment(), realm.disclosureDefaults(), realm.controlLogPath(), realm.controlStoreId(), realm.approvalPolicies(), realm.initialAdministratorPrincipalId());
        return new PkiServerConfiguration(source.version(), source.serverName(), configured, source.listener(), source.authentication(), source.execution(), source.runtime());
    }

    static PkiServerConfiguration configuration(Path root) throws Exception {
        var source = PkiAdminBootstrapTest.configuration(root);
        Path keys = root.resolve("keys");
        try (var password = new KeyringPassword("integration-test-key".toCharArray()); var store = KeyringStore.create(keys, password)) {
            assertTrue(store.aliases().isEmpty());
        }
        var session = source.realm().pkiSessionConfiguration();
        var topology = new PkiSessionConfiguration.SigningTopology(new PkiSessionConfiguration.SigningCoordinatorLimits(
                2, Duration.ofSeconds(10), Duration.ofSeconds(5), Duration.ofDays(1), Duration.ofSeconds(2)),
                List.of(), new PkiSessionConfiguration.SigningLanePool(1, 4));
        var signing = new PkiSessionConfiguration.SigningConfiguration(new ProviderConfig("zeroecho-lib", Map.of(
                "keyringPath", keys.toString(), "operationHorizon", "P90D", "keyRefPrefix", "zeroecho-lib:", "requireComponentSuffix", "true")),
                zeroecho.core.alg.BootstrapAlgorithmIdentities.resolve("SHA384withRSA").orElseThrow().canonicalForm(),
                Duration.ofMinutes(5), Optional.empty(), topology, OptionalLong.empty());
        var configuredSession = new PkiSessionConfiguration(session.version(), session.store(), session.audit(), Optional.of(signing), session.publishers(), session.bindingProviders());
        var realm = source.realm();
        var configuredRealm = new ServerRealmConfiguration(realm.realmId(), realm.displayName(), realm.confirmationProofPolicy(), configuredSession,
                realm.authorityExposure(), realm.authorizationCommitment(), realm.approvalCommitment(), realm.extendedApprovalCommitment(),
                realm.disclosureCommitment(), realm.disclosureDefaults(), realm.controlLogPath(), realm.controlStoreId(), realm.approvalPolicies(), Optional.of("administrator"));
        return new PkiServerConfiguration(source.version(), source.serverName(), configuredRealm, source.listener(), source.authentication(), source.execution(), source.runtime());
    }
}
