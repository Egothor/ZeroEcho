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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.withSettings;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.application.PkiConfigurationChoicesSource;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiOperationExecutor;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiRepository;
import zeroecho.pki.application.PkiResourceScopeResolver;
import zeroecho.pki.application.PkiSelectionExecutor;

final class SelectionGatewayTest {
    @TempDir Path directory;

    @Test
    void disabledSearchIsAbsentFromDiscoveryAndCannotInvokeTheExecutor() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("operator"));
            PkiOperation.SearchCredentials operation = new PkiOperation.SearchCredentials(ServerTestSupport.AUTHORITY,
                    10, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
            OperationSecurityDescriptors.Descriptor descriptor = new OperationSecurityDescriptors().require(operation);
            allow(opened, descriptor.action(), descriptor.resourceType());
            PkiOperationExecutor executor = selectionExecutor();
            ServerOperationGateway gateway = gateway(opened, executor);
            assertFalse(gateway.operationAvailable(operation.name()));
            assertTrue(gateway.discoverableOperations("operator").stream().noneMatch(value -> value.operationId().equals(operation.name())));
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, gateway.execute(request(
                    new AdministrativeOperation.Pki(operation), descriptor.resourceType(), ServerTestSupport.scope(), Optional.empty()),
                    CancellationSignal.NONE));
            org.mockito.Mockito.verify((PkiSelectionExecutor) executor, org.mockito.Mockito.never()).executeSelection(any(), any(), any());
            when(((PkiSelectionExecutor) executor).credentialSearchAvailable()).thenReturn(true);
            assertTrue(gateway.operationAvailable(operation.name()));
            assertTrue(gateway.discoverableOperations("operator").stream().anyMatch(value -> value.operationId().equals(operation.name())));
        }
    }

    @Test
    void broadCollectionAllowStillFiltersEveryGenerationAndPublicationBeforeThePageLimit() throws Exception {
        for (boolean publication : List.of(false, true)) {
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(java.nio.file.Files.createDirectory(directory.resolve(publication ? "publication" : "generation")))) {
                PkiOperation operation = publication ? new PkiOperation.ListPublications(1)
                        : new PkiOperation.ListIssuerGenerations(ServerTestSupport.AUTHORITY, 1, Optional.empty());
                OperationSecurityDescriptors.Descriptor descriptor = new OperationSecurityDescriptors().require(operation);
                opened.store().createPrincipal(ServerTestSupport.principal("operator"));
                allow(opened, descriptor.action(), descriptor.resourceType());
                deny(opened, "deny-profile", descriptor.action(), descriptor.resourceType(), scope("issuer-a", "hidden"));
                deny(opened, "deny-issuer", descriptor.action(), descriptor.resourceType(), scope("issuer-denied", null));
                String identity = publication ? "publicationId" : "issuerId";
                String collection = publication ? "publications" : "generations";
                List<PkiOperationValue.ObjectValue> candidates = List.of(
                        row(identity, "a", "issuer-a", "hidden"), row(identity, "b", "issuer-denied", "visible"),
                        row(identity, "c", "issuer-c", "visible"), row(identity, "d", "issuer-d", "visible"));
                // Generation IDs are also the authoritative issuer dimension.
                if (!publication) {
                    candidates = List.of(row(identity, "a", "a", "hidden"), row(identity, "issuer-denied", "issuer-denied", "visible"),
                            row(identity, "c", "c", "visible"), row(identity, "d", "d", "visible"));
                    deny(opened, "deny-generation-profile", descriptor.action(), descriptor.resourceType(), scope(null, "hidden"));
                }
                List<PkiOperationValue.ObjectValue> rows = candidates;
                AtomicInteger visits = new AtomicInteger();
                PkiOperationExecutor executor = selectionExecutor();
                when(((PkiSelectionExecutor) executor).executeSelection(any(), any(), any())).thenAnswer(call -> {
                    Predicate<PkiOperationValue.ObjectValue> include = call.getArgument(1);
                    List<PkiOperationValue.ObjectValue> accepted = rows.stream().filter(candidate -> {
                        visits.incrementAndGet(); return include.test(candidate);
                    }).toList();
                    Map<String, PkiOperationValue> fields = Map.of("count", new PkiOperationValue.IntegerValue(1),
                            "truncated", new PkiOperationValue.BooleanValue(accepted.size() > 1),
                            "nextCursor", accepted.getFirst().fields().get(identity),
                            collection, new PkiOperationValue.ListValue(List.of(accepted.getFirst())));
                    return new PkiOperationOutcome.Completed(new PkiOperationResult(operation.name(), fields));
                });
                ServerOperationGateway gateway = gateway(opened, executor);
                Permission.Scope collectionScope = publication ? realmScope() : ServerTestSupport.scope();
                ServerOperationGateway.Outcome.Executed outcome = assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,
                        gateway.execute(request(new AdministrativeOperation.Pki(operation), descriptor.resourceType(), collectionScope, Optional.empty()), CancellationSignal.NONE));
                PkiOperationResult result = assertInstanceOf(PkiOperationOutcome.Completed.class, outcome.outcome()).result();
                assertEquals(text("c"), result.fields().get("nextCursor"));
                assertEquals(4, visits.get());
                assertFalse(result.toString().contains("hidden"));
                deny(opened, "deny-all", descriptor.action(), descriptor.resourceType(), collectionScope);
                assertInstanceOf(ServerOperationGateway.Outcome.Denied.class,
                        gateway.execute(request(new AdministrativeOperation.Pki(operation), descriptor.resourceType(), collectionScope, Optional.empty()), CancellationSignal.NONE));
                assertEquals(4, visits.get(), "Explicit collection denial must not scan rows");
            }
        }
    }

    @Test
    void capabilityPagesContainOnlyTheAuthorizedObjectsNonBearerMetadataAndHonorProfileDeny() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            opened.store().createPrincipal(ServerTestSupport.principal("operator"));
            allow(opened, Permission.Action.DISCLOSURE_READ, Permission.ResourceType.DISCLOSURE);
            PkiId objectId = new PkiId("credential-a");
            opened.store().createDisclosure(new DisclosureService.Record(objectId, DisclosureService.ObjectType.LEAF_CERTIFICATE,
                    DisclosureService.Policy.PUBLIC_UNLISTED, Optional.empty(), Optional.empty(), ServerTestSupport.DIGEST, ServerTestSupport.CLOCK.instant()));
            for (String id : List.of("cap-z", "cap-a", "cap-m")) {
                opened.store().createCapability(new DisclosureService.Capability(id, ServerTestSupport.REALM, objectId, "RETRIEVE",
                        "operator", new byte[32], ServerTestSupport.CLOCK.instant().plusSeconds(600), false));
            }
            opened.store().createCapability(new DisclosureService.Capability("cap-hidden", ServerTestSupport.REALM,
                    new PkiId("credential-other"), "RETRIEVE", "operator", new byte[32], ServerTestSupport.CLOCK.instant().plusSeconds(600), false));
            PkiOperationExecutor executor = selectionExecutor();
            when(executor.execute(any(), any())).thenReturn(new PkiOperationOutcome.Completed(new PkiOperationResult("credential.inspect",
                    row("credentialId", objectId.value(), "issuer-a", "profile-a").fields())));
            ServerOperationGateway gateway = gateway(opened, executor);
            List<String> seen = new ArrayList<>();
            Optional<String> cursor = Optional.empty();
            do {
                ServerControlOperation.ListCapabilities operation = new ServerControlOperation.ListCapabilities(objectId, 1, cursor);
                PkiOperationValue.ObjectValue page = controlValue(gateway.execute(request(new AdministrativeOperation.Control(operation),
                        Permission.ResourceType.DISCLOSURE, realmScope(), Optional.of(objectId)), CancellationSignal.NONE));
                PkiOperationValue.ListValue rows = (PkiOperationValue.ListValue) page.fields().get("items");
                PkiOperationValue.ObjectValue row = (PkiOperationValue.ObjectValue) rows.values().getFirst();
                assertEquals(Set.of("capabilityId", "objectId", "expiresAt", "revoked"), row.fields().keySet());
                assertEquals(text(objectId.value()), row.fields().get("objectId"));
                seen.add(((PkiOperationValue.Text) row.fields().get("capabilityId")).value());
                cursor = Optional.ofNullable(page.fields().get("nextCursor")).map(value -> ((PkiOperationValue.Text) value).value());
            } while (cursor.isPresent());
            assertEquals(List.of("cap-a", "cap-m", "cap-z"), seen);
            deny(opened, "deny-profile", Permission.Action.DISCLOSURE_READ, Permission.ResourceType.DISCLOSURE, scope(null, "profile-a"));
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, gateway.execute(request(
                    new AdministrativeOperation.Control(new ServerControlOperation.ListCapabilities(objectId, 1, Optional.empty())),
                    Permission.ResourceType.DISCLOSURE, realmScope(), Optional.of(objectId)), CancellationSignal.NONE));
        }
    }

    @Test
    void configurationNeedsItsExistingPermissionAndNeverProjectsSecretsOrUnconfiguredAcmeProviders() throws Exception {
        try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(directory)) {
            SecurityPrincipal principal = ServerTestSupport.principal("operator");
            opened.store().createPrincipal(principal);
            AtomicInteger calls = new AtomicInteger();
            PkiOperationExecutor executor = selectionExecutor();
            when(((PkiConfigurationChoicesSource) executor).configurationChoices(org.mockito.ArgumentMatchers.anyInt(), any(), any())).thenAnswer(call -> {
                calls.incrementAndGet();
                return new PkiConfigurationChoicesSource.Choices(List.of(new zeroecho.pki.api.FormatId("x509")), List.of("local"),
                        List.of(new zeroecho.pki.api.publication.PublicationTarget(zeroecho.pki.api.publication.PublicationTargetType.FILESYSTEM, "mirror")),
                        List.of(new zeroecho.pki.api.KeyRef("local:key.prv")), Optional.of("local:key.prv"), List.of("Ed25519"));
            });
            ServerOperationGateway gateway = gateway(opened, executor);
            ServerOperationGateway.Request request = request(new AdministrativeOperation.Control(new ServerControlOperation.ConfigurationChoices(1, Optional.empty())),
                    Permission.ResourceType.SERVER_CONFIGURATION, realmScope(), Optional.empty());
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, gateway.execute(request, CancellationSignal.NONE));
            assertEquals(0, calls.get());
            allow(opened, Permission.Action.SERVER_CONFIGURATION_READ, Permission.ResourceType.SERVER_CONFIGURATION);
            PkiOperationValue.ObjectValue value = controlValue(gateway.execute(request, CancellationSignal.NONE));
            assertEquals(Set.of("formats", "signingProviders", "publicationTargets", "keys", "algorithms", "acmeChallengeProviders", "acmeEabProviders"), value.fields().keySet());
            assertEquals(new PkiOperationValue.ListValue(List.of()), value.fields().get("acmeChallengeProviders"));
            assertEquals(new PkiOperationValue.ListValue(List.of()), value.fields().get("acmeEabProviders"));
            assertFalse(value.toString().contains("options"));
            opened.store().replacePrincipal(principal, new SecurityPrincipal(principal.principalId(), principal.type(), principal.displayName(),
                    principal.organization(), principal.attributes(), false));
            assertInstanceOf(ServerOperationGateway.Outcome.Denied.class, gateway.execute(request, CancellationSignal.NONE));
            assertEquals(1, calls.get());
        }
    }

    private static PkiOperationExecutor selectionExecutor() {
        return mock(PkiOperationExecutor.class, withSettings().extraInterfaces(PkiSelectionExecutor.class, PkiConfigurationChoicesSource.class));
    }
    private static void allow(ServerTestSupport.OpenedStore opened, Permission.Action action, Permission.ResourceType type) {
        opened.store().createGrant(ServerTestSupport.grant("allow", "operator", Permission.Effect.ALLOW, action, type,
                realmScope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
    }
    private static void deny(ServerTestSupport.OpenedStore opened, String id, Permission.Action action, Permission.ResourceType type, Permission.Scope scope) {
        opened.store().createGrant(ServerTestSupport.grant(id, "operator", Permission.Effect.DENY, action, type,
                scope, Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED));
    }
    private static Permission.Scope realmScope() { return new Permission.Scope(ServerTestSupport.REALM, Optional.empty(), Optional.empty(), Optional.empty()); }
    private static Permission.Scope scope(String issuer, String profile) { return new Permission.Scope(ServerTestSupport.REALM, Optional.of(ServerTestSupport.AUTHORITY),
            Optional.ofNullable(issuer).map(PkiId::new), Optional.ofNullable(profile)); }
    private static PkiOperationValue.Text text(String value) { return new PkiOperationValue.Text(value); }
    private static PkiOperationValue.ObjectValue row(String identity, String id, String issuer, String profile) {
        Map<String, PkiOperationValue> fields = new java.util.LinkedHashMap<>();
        fields.put(identity, text(id)); fields.put("authorityId", text(ServerTestSupport.AUTHORITY.value()));
        fields.put("issuerId", text(issuer)); fields.put("profileId", text(profile));
        return new PkiOperationValue.ObjectValue(fields);
    }
    private static ServerOperationGateway.Request request(AdministrativeOperation operation, Permission.ResourceType type, Permission.Scope scope, Optional<PkiId> objectId) {
        return new ServerOperationGateway.Request(ServerTestSupport.REALM, "operator", operation,
                new Permission.Resource(type, scope, objectId, Optional.empty()), Permission.Relationship.ANY,
                Permission.Context.empty(), Optional.empty(), "selection-test");
    }
    private static PkiOperationValue.ObjectValue controlValue(ServerOperationGateway.Outcome outcome) {
        ServerOperationGateway.Outcome.ControlExecuted executed = assertInstanceOf(ServerOperationGateway.Outcome.ControlExecuted.class, outcome);
        ServerControlOperationOutcome.Ordinary ordinary = assertInstanceOf(ServerControlOperationOutcome.Ordinary.class, executed.outcome());
        PkiOperationOutcome.Completed completed = assertInstanceOf(PkiOperationOutcome.Completed.class, ordinary.outcome());
        return assertInstanceOf(PkiOperationValue.ObjectValue.class, completed.result().fields().get("value"));
    }
    private static ServerOperationGateway gateway(ServerTestSupport.OpenedStore opened, PkiOperationExecutor executor) {
        DisclosureService disclosure = new DisclosureService(ServerTestSupport.REALM, opened.store(), DisclosureService.Defaults.recommended(),
                ServerTestSupport.CLOCK, new SecureRandom(), opened.audit());
        CredentialPublicationGate publication = new CredentialPublicationGate(mock(PkiRepository.class), mock(ProfileService.class),
                mock(CredentialConfirmationService.class), disclosure, ServerTestSupport.CLOCK, () -> { });
        return new ServerOperationGateway(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), true), opened.store(),
                RoleTemplateCatalog.load(SelectionGatewayTest.class.getClassLoader()), new AuthorizationEngine(ServerTestSupport.CLOCK),
                new ApprovalService(opened.store(), ServerTestSupport.CLOCK, opened.audit()), new BreakGlassService(opened.store(), ServerTestSupport.CLOCK, opened.audit()),
                disclosure, publication, new AuditorViews(ServerTestSupport.CLOCK, opened.audit()), Optional.empty(), new OperationSecurityDescriptors(),
                executor, (request, evidence, cancellation) -> { throw new AssertionError("Signing not expected"); }, mock(PkiResourceScopeResolver.class), Map.of(),
                profile -> zeroecho.pki.api.profile.IssuanceApprovalRequirement.NONE, ServerTestSupport.CLOCK, opened.audit(), () -> { });
    }
}
