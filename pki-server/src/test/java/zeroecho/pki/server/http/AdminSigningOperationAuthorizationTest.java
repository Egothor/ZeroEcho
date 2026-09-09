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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import java.time.Clock;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.SigningOperationAuthorization;
import zeroecho.pki.server.AuthorizationEngine;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.RealmId;
import zeroecho.pki.server.ServerOperationGateway;
import zeroecho.pki.server.ServerRealmConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/** Current-principal authorization coverage for private signing status. */
class AdminSigningOperationAuthorizationTest {
    private static final RealmId REALM = new RealmId("current");
    private static final PkiId OPERATION = new PkiId("signing:private");
    private static final String REQUEST = "request-authorization";

    @Test
    void authorizedRequesterAndAnotherAuthorizedAdministratorCanRead() {
        Fixture fixture = fixture(issuance());
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString()))
                .thenAnswer(invocation -> decision(!"unauthorized".equals(invocation.getArgument(0))));

        HttpResponses.Response requester = fixture.handler().signingOperation(REQUEST, "requester",
                OPERATION.value());
        HttpResponses.Response administrator = fixture.handler().signingOperation(REQUEST, "administrator",
                OPERATION.value());

        assertEquals(202, requester.statusCode());
        assertEquals(202, administrator.statusCode());
        assertTrue(requester.oneTimeSensitive());
        assertEquals(Optional.empty(), requester.capabilityId());
    }

    @Test
    void leakedIdentifierUnauthorizedAndCrossRealmAuthorityAreIndistinguishableFromAbsent() {
        Fixture fixture = fixture(issuance());
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString()))
                .thenReturn(decision(false));

        HttpResponses.Response leaked = fixture.handler().signingOperation(REQUEST, "unauthorized",
                OPERATION.value());
        HttpResponses.Response crossRealm = fixture.handler().signingOperation(REQUEST, "cross-realm-admin",
                OPERATION.value());
        when(fixture.session().signingOperationAuthorization(OPERATION)).thenReturn(Optional.empty());
        HttpResponses.Response absent = fixture.handler().signingOperation(REQUEST, "unauthorized",
                OPERATION.value());

        assertEquals(404, leaked.statusCode());
        assertEquals(404, crossRealm.statusCode());
        assertEquals(404, absent.statusCode());
        assertArrayEquals(absent.body(), leaked.body());
        assertArrayEquals(absent.body(), crossRealm.body());
        assertTrue(leaked.oneTimeSensitive());
        assertTrue(crossRealm.oneTimeSensitive());
        assertTrue(absent.oneTimeSensitive());
        verify(fixture.session(), never()).signingOperation(OPERATION);
    }

    @Test
    void everyDomainProjectionMapsToItsExactRbacActionAndResource() {
        assertMapping(new SigningOperationAuthorization(SigningOperationAuthorization.Action.AUTHORITY_CREATE,
                        SigningOperationAuthorization.ResourceType.AUTHORITY, Optional.empty(),
                        Optional.empty(), Optional.empty()),
                Permission.Action.AUTHORITY_CREATE, Permission.ResourceType.AUTHORITY);
        assertMapping(new SigningOperationAuthorization(SigningOperationAuthorization.Action.ISSUER_CREATE,
                        SigningOperationAuthorization.ResourceType.ISSUER, Optional.of(new PkiId("ca:subject")),
                        Optional.of("intermediate"), Optional.empty()),
                Permission.Action.ISSUER_CREATE, Permission.ResourceType.ISSUER);
        assertMapping(issuance(), Permission.Action.CERTIFICATE_ISSUE, Permission.ResourceType.CERTIFICATE);
        assertMapping(new SigningOperationAuthorization(SigningOperationAuthorization.Action.STATUS_GENERATE,
                        SigningOperationAuthorization.ResourceType.STATUS_OBJECT,
                        Optional.of(new PkiId("ca:issuer")), Optional.empty(), Optional.empty()),
                Permission.Action.CRL_GENERATE, Permission.ResourceType.STATUS_OBJECT);
    }

    private static void assertMapping(SigningOperationAuthorization authorization,
            Permission.Action expectedAction, Permission.ResourceType expectedType) {
        Fixture fixture = fixture(authorization);
        when(fixture.gateway().authorizeControl(anyString(), any(), any(), any(), anyString()))
                .thenReturn(decision(true));
        fixture.handler().signingOperation(REQUEST, "administrator", OPERATION.value());
        ArgumentCaptor<Permission.Action> action = ArgumentCaptor.forClass(Permission.Action.class);
        ArgumentCaptor<Permission.Resource> resource = ArgumentCaptor.forClass(Permission.Resource.class);
        verify(fixture.gateway()).authorizeControl(anyString(), action.capture(), resource.capture(),
                any(), anyString());
        assertEquals(expectedAction, action.getValue());
        assertEquals(expectedType, resource.getValue().type());
        assertEquals(REALM, resource.getValue().scope().realmId());
        assertEquals(authorization.authorityId(), resource.getValue().scope().authorityId());
        assertEquals(authorization.profileId(), resource.getValue().scope().profileId());
        assertEquals(authorization.objectId(), resource.getValue().objectId());
    }

    private static SigningOperationAuthorization issuance() {
        return new SigningOperationAuthorization(SigningOperationAuthorization.Action.CERTIFICATE_ISSUE,
                SigningOperationAuthorization.ResourceType.CERTIFICATE,
                Optional.of(new PkiId("ca:issuer")), Optional.of("leaf"), Optional.empty());
    }

    private static AuthorizationEngine.Decision decision(boolean allowed) {
        return new AuthorizationEngine.Decision(allowed
                ? AuthorizationEngine.Code.ALLOWED : AuthorizationEngine.Code.NO_MATCHING_GRANT, false);
    }

    private static Fixture fixture(SigningOperationAuthorization authorization) {
        PkiSession session = mock(PkiSession.class);
        when(session.signingOperationAuthorization(OPERATION)).thenReturn(Optional.of(authorization));
        when(session.signingOperation(OPERATION)).thenReturn(new PkiOperationOutcome.Pending(
                "signing.operation", OPERATION));
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
        return new Fixture(handler, session, gateway);
    }

    private record Fixture(AdminHttpHandler handler, PkiSession session, ServerOperationGateway gateway) { }
}
