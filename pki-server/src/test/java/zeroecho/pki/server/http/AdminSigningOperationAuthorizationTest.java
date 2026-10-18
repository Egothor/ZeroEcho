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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.inOrder;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.api.signing.SemanticSigningKind;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.signing.SemanticSigningScope;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SigningOperationState;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSigningCommands;
import zeroecho.pki.application.PkiOperationResult;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.AuthorizationEngine;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerOperationGateway;
import zeroecho.pki.server.ServerRealmConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/** Private polling authorizes the same immutable semantic observation it projects. */
class AdminSigningOperationAuthorizationTest {
    private static final RealmId REALM = new RealmId("current");
    private static final PkiId OPERATION = new PkiId("signing:private");
    private static final PkiId PARENT = new PkiId("ca:issuer");
    private static final PkiId SUBJECT = new PkiId("ca:subject");
    private static final String REQUEST = "request-authorization";

    @Test
    void authorizedRequesterAndAnotherAuthorizedAdministratorCanRead() {
        Fixture fixture = fixture(issuance());
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString()))
                .thenAnswer(invocation -> decision(!"unauthorized".equals(invocation.getArgument(0))));
        HttpResponses.Response requester = fixture.handler().signingOperation(REQUEST, "requester", OPERATION.value());
        HttpResponses.Response administrator = fixture.handler().signingOperation(REQUEST, "administrator", OPERATION.value());
        assertEquals(202, requester.statusCode());
        assertEquals(202, administrator.statusCode());
        assertTrue(requester.oneTimeSensitive());
        assertEquals(Optional.empty(), requester.capabilityId());
        assertEquals(Optional.of("/admin/v1/signing-operations/" + OPERATION.value()), requester.statusLocation());
        verify(fixture.signing(), times(2)).find(OPERATION);
    }

    @Test
    void leakedIdentifierUnauthorizedAndCrossRealmAuthorityAreIndistinguishableFromAbsent() {
        Fixture fixture = fixture(issuance());
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString())).thenReturn(decision(false));
        HttpResponses.Response leaked = fixture.handler().signingOperation(REQUEST, "unauthorized", OPERATION.value());
        HttpResponses.Response foreign = fixture.handler().signingOperation(REQUEST, "cross-realm-admin", OPERATION.value());
        when(fixture.signing().find(OPERATION)).thenReturn(Optional.empty());
        HttpResponses.Response absent = fixture.handler().signingOperation(REQUEST, "unauthorized", OPERATION.value());
        assertEquals(404, leaked.statusCode());
        assertEquals(404, foreign.statusCode());
        assertEquals(404, absent.statusCode());
        assertArrayEquals(absent.body(), leaked.body());
        assertArrayEquals(absent.body(), foreign.body());
        assertTrue(leaked.oneTimeSensitive());
        verify(fixture.signing(), times(3)).find(OPERATION);
    }

    @Test
    void everyDomainProjectionMapsToItsExactRbacActionAndResource() {
        assertMapping(scope(SemanticSigningKind.CA, "CREATE_ROOT", "ca.create"),
                Permission.Action.AUTHORITY_CREATE, Permission.ResourceType.AUTHORITY, Optional.empty(),
                Optional.empty(), Optional.empty());
        assertMapping(scope(SemanticSigningKind.CA, "CREATE_INTERMEDIATE", "ca.intermediate.create"),
                Permission.Action.AUTHORITY_CREATE, Permission.ResourceType.AUTHORITY, Optional.of(PARENT),
                Optional.of("profile"), Optional.of(SUBJECT));
        assertMapping(scope(SemanticSigningKind.CA, "ISSUE_INTERMEDIATE", "ca.intermediate.issue"),
                Permission.Action.ISSUER_CREATE, Permission.ResourceType.ISSUER, Optional.of(SUBJECT),
                Optional.of("profile"), Optional.empty());
        assertMapping(issuance(), Permission.Action.CERTIFICATE_ISSUE, Permission.ResourceType.CERTIFICATE,
                Optional.of(PARENT), Optional.of("profile"), Optional.empty());
        assertMapping(scope(SemanticSigningKind.STATUS, "GENERATE_FULL_CRL", "status.generate"),
                Permission.Action.CRL_GENERATE, Permission.ResourceType.STATUS_OBJECT,
                Optional.of(PARENT), Optional.empty(), Optional.empty());
    }

    @Test
    void rolloverAndRotationUseSubjectAuthorityReadIndependentOfMutationPurpose() {
        for (String purpose : java.util.List.of("ca.rollover", "ca.rotate")) {
            assertMapping(scope(SemanticSigningKind.CA, "ROLLOVER_ROOT", purpose),
                    Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY,
                    Optional.of(PARENT), Optional.of("profile"), Optional.of(PARENT));
            assertMapping(scope(SemanticSigningKind.CA, "ROLLOVER_INTERMEDIATE", purpose),
                    Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY,
                    Optional.of(SUBJECT), Optional.of("profile"), Optional.of(SUBJECT));
        }
    }

    @Test
    void readPermissionAllowsPollingAndMutationPermissionAloneDoesNot() {
        Fixture fixture = fixture(scope(SemanticSigningKind.CA, "ROLLOVER_INTERMEDIATE", "ca.rotate"));
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString()))
                .thenAnswer(invocation -> decision("reader".equals(invocation.getArgument(0))
                        && invocation.getArgument(1) == Permission.Action.AUTHORITY_READ));
        assertEquals(202, fixture.handler().signingOperation(REQUEST, "reader", OPERATION.value()).statusCode());
        assertEquals(404, fixture.handler().signingOperation(REQUEST, "rotation-only", OPERATION.value()).statusCode());
    }

    @Test
    void completedProjectionUsesOnlyTheAuthorizedSnapshot() {
        Fixture fixture = fixture(issuance());
        SemanticSigningOperation completed = completedObservation(issuance());
        when(fixture.signing().find(OPERATION)).thenReturn(Optional.of(completed));
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString()))
                .thenReturn(decision(true));
        when(fixture.commands().completedResult(completed)).thenReturn(new PkiOperationResult("signing.operation",
                Map.of("operationId", new PkiOperationValue.Text(OPERATION.value()),
                        "kind", new PkiOperationValue.Text("ISSUANCE"),
                        "encoding", new PkiOperationValue.Text("DER"),
                        "resultSha256", new PkiOperationValue.Text("ab".repeat(32)),
                        "credentialId", new PkiOperationValue.Text("x509:credential"))));
        HttpResponses.Response response = fixture.handler().signingOperation(REQUEST, "administrator", OPERATION.value());
        assertEquals(200, response.statusCode());
        String body = new String(response.body(), StandardCharsets.UTF_8);
        assertTrue(body.contains("\"credentialId\":\"x509:credential\""));
        assertTrue(body.contains("\"resultSha256\":\"" + "ab".repeat(32) + "\""));
        InOrder order = inOrder(fixture.signing(), fixture.gateway(), fixture.commands());
        order.verify(fixture.signing()).find(OPERATION);
        order.verify(fixture.gateway()).authorizeControl(anyString(), any(), any(), any(), anyString());
        order.verify(fixture.commands()).completedResult(same(completed));
        order.verifyNoMoreInteractions();
    }

    @Test
    void deniedCompletedResultIsHiddenWithoutProjection() {
        Fixture fixture = fixture(issuance());
        when(fixture.signing().find(OPERATION)).thenReturn(Optional.of(completedObservation(issuance())));
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString()))
                .thenReturn(decision(false));
        HttpResponses.Response response = fixture.handler().signingOperation(REQUEST, "unauthorized", OPERATION.value());
        assertEquals(404, response.statusCode());
        assertArrayEquals(HttpResponses.signingNotFound(REQUEST).body(), response.body());
        verify(fixture.commands(), never()).completedResult(any());
        verify(fixture.signing()).find(OPERATION);
    }

    private static SemanticSigningOperation completedObservation(SemanticSigningScope scope) {
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        return new SemanticSigningOperation(new SigningSubmissionId(OPERATION, "test", now), scope,
                SigningOperationState.SUCCEEDED, SemanticSigningState.COMPLETED, 1, 1,
                now, now.plusSeconds(60), Optional.empty(), Optional.of(new EncodedObject(Encoding.DER, new byte[]{1, 2, 3})));
    }

    private static void assertMapping(SemanticSigningScope scope, Permission.Action expectedAction,
            Permission.ResourceType expectedType, Optional<PkiId> authority, Optional<String> profile,
            Optional<PkiId> object) {
        Fixture fixture = fixture(scope);
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString())).thenReturn(decision(true));
        fixture.handler().signingOperation(REQUEST, "administrator", OPERATION.value());
        ArgumentCaptor<Permission.Action> action = ArgumentCaptor.forClass(Permission.Action.class);
        ArgumentCaptor<Permission.Resource> resource = ArgumentCaptor.forClass(Permission.Resource.class);
        verify(fixture.gateway()).authorizeControl(anyString(), action.capture(), resource.capture(), any(), anyString());
        verify(fixture.signing()).find(OPERATION);
        assertEquals(expectedAction, action.getValue());
        assertEquals(expectedType, resource.getValue().type());
        assertEquals(REALM, resource.getValue().scope().realmId());
        assertEquals(authority, resource.getValue().scope().authorityId());
        assertEquals(profile, resource.getValue().scope().profileId());
        assertEquals(object, resource.getValue().objectId());
    }

    private static SemanticSigningScope issuance() {
        return scope(SemanticSigningKind.ISSUANCE, "ISSUE_END_ENTITY", "credential.issue");
    }

    private static SemanticSigningScope scope(SemanticSigningKind kind, String operation, String purpose) {
        return new SemanticSigningScope(kind, operation,
                new AccessContext(new Principal("ADMIN_PRINCIPAL", "requester"), new Purpose(purpose),
                        Optional.empty(), Optional.empty()), new KeyRef("key:signing"),
                operation.equals("CREATE_ROOT") ? Optional.empty() : Optional.of(PARENT),
                operation.contains("INTERMEDIATE") ? Optional.of(SUBJECT) : Optional.empty(),
                kind == SemanticSigningKind.STATUS ? Optional.empty() : Optional.of("profile"), Optional.empty());
    }

    private static AuthorizationEngine.Decision decision(boolean allowed) {
        return new AuthorizationEngine.Decision(allowed
                ? AuthorizationEngine.Code.ALLOWED : AuthorizationEngine.Code.NO_MATCHING_GRANT, false);
    }

    private static Fixture fixture(SemanticSigningScope scope) {
        PkiSession session = mock(PkiSession.class);
        SemanticSigningService signing = mock(SemanticSigningService.class);
        PkiSigningCommands commands = mock(PkiSigningCommands.class);
        when(session.semanticSigning()).thenReturn(Optional.of(signing));
        when(session.signingCommands()).thenReturn(Optional.of(commands));
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        when(signing.find(OPERATION)).thenReturn(Optional.of(new SemanticSigningOperation(
                new SigningSubmissionId(OPERATION, "test", now), scope, SigningOperationState.PENDING,
                SemanticSigningState.SIGNING, 0, 0, now, now.plusSeconds(60), Optional.empty(), Optional.empty())));
        ServerOperationGateway gateway = mock(ServerOperationGateway.class);
        ServerRealmContext realm = mock(ServerRealmContext.class);
        when(realm.session()).thenReturn(session);
        when(realm.gateway()).thenReturn(gateway);
        PkiServerConfiguration configuration = mock(PkiServerConfiguration.class);
        ServerRealmConfiguration realmConfiguration = mock(ServerRealmConfiguration.class);
        when(configuration.realm()).thenReturn(realmConfiguration);
        when(realmConfiguration.realmId()).thenReturn(REALM);
        AdminHttpHandler handler = new AdminHttpHandler(configuration, realm,
                mock(PkiServerAuthenticator.class), mock(ServerRuntime.class), Clock.systemUTC(),
                new RequestIds(new SecureRandom()), () -> true);
        return new Fixture(handler, signing, commands, gateway);
    }

    private record Fixture(AdminHttpHandler handler, SemanticSigningService signing,
            PkiSigningCommands commands, ServerOperationGateway gateway) { }
}
