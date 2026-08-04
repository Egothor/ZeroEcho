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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

/** Authorization and immutable built-in role-template coverage. */
class AuthorizationAndRoleTest {
    @Test
    void defaultsToDenyAndExplicitDenyOverridesAllow() {
        System.out.println("defaultsToDenyAndExplicitDenyOverridesAllow");
        AuthorizationEngine engine = new AuthorizationEngine(ServerTestSupport.CLOCK);
        SecurityPrincipal principal = ServerTestSupport.principal("officer");
        AuthorizationEngine.Request empty = request(principal, List.of(), Permission.DataView.METADATA_REDACTED);
        assertEquals(AuthorizationEngine.Code.NO_MATCHING_GRANT, engine.authorize(empty).code());
        Permission.Grant allow = ServerTestSupport.grant("allow", "officer", Permission.Effect.ALLOW,
                Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY, ServerTestSupport.scope(),
                Permission.Relationship.ANY, Permission.DataView.METADATA_FULL);
        Permission.Grant deny = ServerTestSupport.grant("deny", "officer", Permission.Effect.DENY,
                Permission.Action.AUTHORITY_READ, Permission.ResourceType.AUTHORITY, ServerTestSupport.scope(),
                Permission.Relationship.ANY, Permission.DataView.METADATA_FULL);
        assertEquals(AuthorizationEngine.Code.ALLOWED,
                engine.authorize(request(principal, List.of(allow), Permission.DataView.METADATA_REDACTED)).code());
        assertEquals(AuthorizationEngine.Code.EXPLICITLY_DENIED,
                engine.authorize(request(principal, List.of(allow, deny), Permission.DataView.METADATA_REDACTED)).code());
        System.out.println("...decisions=default-deny,allow,explicit-deny");
        System.out.println("...ok");
    }

    @Test
    void enforcesAuthorityOwnershipViewsExpiryAndDisabledPrincipal() {
        System.out.println("enforcesAuthorityOwnershipViewsExpiryAndDisabledPrincipal");
        AuthorizationEngine engine = new AuthorizationEngine(ServerTestSupport.CLOCK);
        SecurityPrincipal principal = ServerTestSupport.principal("requester");
        Permission.Resource owned = new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                ServerTestSupport.scope(), Optional.of(new zeroecho.pki.api.PkiId("credential-a")),
                Optional.of("requester"));
        Permission.Grant own = new Permission.Grant("own", "requester", Permission.Effect.ALLOW,
                Permission.Action.CERTIFICATE_READ_METADATA, Permission.ResourceType.CERTIFICATE,
                ServerTestSupport.scope(), Permission.Relationship.OWN, Permission.DataView.METADATA_REDACTED,
                Set.of(), Optional.empty(), true);
        AuthorizationEngine.Request accepted = new AuthorizationEngine.Request(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), false),
                principal, Permission.Action.CERTIFICATE_READ_METADATA, owned, Permission.Relationship.OWN,
                Permission.DataView.METADATA_REDACTED, Permission.Context.empty(), List.of(own), Set.of());
        assertTrue(engine.authorize(accepted).allowed());
        Permission.Grant expired = new Permission.Grant("expired", "requester", Permission.Effect.ALLOW,
                own.action(), own.resourceType(), own.scope(), own.relationship(), own.dataView(), Set.of(),
                Optional.of(Instant.parse("2026-08-04T11:59:59Z")), true);
        assertEquals(AuthorizationEngine.Code.GRANT_EXPIRED,
                engine.authorize(new AuthorizationEngine.Request(accepted.realmId(), accepted.exposure(), principal,
                        accepted.action(), owned, accepted.relationship(), accepted.dataView(), accepted.context(),
                        List.of(expired), Set.of())).code());
        SecurityPrincipal disabled = new SecurityPrincipal("requester", SecurityPrincipal.Type.USER, "Requester",
                Optional.empty(), Map.of(), false);
        assertEquals(AuthorizationEngine.Code.PRINCIPAL_DISABLED,
                engine.authorize(new AuthorizationEngine.Request(accepted.realmId(), accepted.exposure(), disabled,
                        accepted.action(), owned, accepted.relationship(), accepted.dataView(), accepted.context(),
                        List.of(own), Set.of())).code());
        System.out.println("...ownership=true, expiry=closed, disabled=closed");
        System.out.println("...ok");
    }

    @Test
    void loadsExactTemplatesAndRejectsUnknownSchemaFields() throws Exception {
        System.out.println("loadsExactTemplatesAndRejectsUnknownSchemaFields");
        RoleTemplateCatalog catalog = RoleTemplateCatalog.load(getClass().getClassLoader());
        assertEquals(15, catalog.templates().size());
        assertTrue(catalog.templates().stream().anyMatch(item -> item.templateId().equals("platform-operator")));
        assertFalse(catalog.templates().stream().anyMatch(item -> item.templateId().contains("owner")));
        assertFalse(catalog.templates().stream().anyMatch(item -> item.actions()
                .contains(Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY)));
        RoleTemplateCatalog.Assignment requester = new RoleTemplateCatalog.Assignment("requester-role",
                "requester", "requester", 1, ServerTestSupport.scope(), true);
        assertTrue(catalog.instantiate(requester).stream()
                .filter(item -> item.action() == Permission.Action.CERTIFICATE_READ_METADATA)
                .allMatch(item -> item.relationship() == Permission.Relationship.OWN));
        byte[] source;
        try (java.io.InputStream input = getClass().getClassLoader()
                .getResourceAsStream(RoleTemplateCatalog.RESOURCE)) {
            source = java.util.Objects.requireNonNull(input).readAllBytes();
        }
        String hostile = new String(source, StandardCharsets.UTF_8).replaceFirst("\\{",
                "{\"unknown\":true,");
        assertThrows(IllegalArgumentException.class,
                () -> RoleTemplateCatalog.parse(hostile.getBytes(StandardCharsets.UTF_8)));
        System.out.println("...templates=" + catalog.templates().size());
        System.out.println("...ok");
    }

    private static AuthorizationEngine.Request request(SecurityPrincipal principal, List<Permission.Grant> grants,
            Permission.DataView view) {
        return new AuthorizationEngine.Request(ServerTestSupport.REALM,
                new AuthorityExposurePolicy(AuthorityExposurePolicy.Mode.ALL_REALM_AUTHORITIES, Set.of(), false),
                principal, Permission.Action.AUTHORITY_READ, ServerTestSupport.authorityResource(),
                Permission.Relationship.ANY, view, Permission.Context.empty(), grants, Set.of());
    }
}
