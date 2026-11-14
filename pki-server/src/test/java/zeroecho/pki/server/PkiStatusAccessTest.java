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

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;

/** Explicit status capability migration preserves historical grants and never implies root or certificate access. */
class PkiStatusAccessTest {
    @TempDir Path directory;
    @Test void migratesOnlyStatusCapabilitiesIdempotentlyAndRefusesChangedState() throws Exception {
        var configuration = AdministrativeWorkflowFixture.configuration(directory, false);
        PkiCertificateAccessTest.legacy(configuration);
        PkiAdminBootstrap.provisionStatusAccess(configuration, "bootstrap-admin", "bootstrap-approver", "trusted-proxy");
        for (int attempt = 0; attempt < 2; attempt++) {
            try (var realm = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
                for (String id : java.util.List.of("bootstrap-admin", "bootstrap-approver")) {
                    var grants = realm.directGrants(id);
                    org.junit.jupiter.api.Assertions.assertEquals(1, grants.stream().filter(g -> g.action() == Permission.Action.CRL_DOWNLOAD && g.dataView() == Permission.DataView.CONTENT_FULL && g.resourceType() == Permission.ResourceType.STATUS_OBJECT && g.enabled()).count());
                    org.junit.jupiter.api.Assertions.assertTrue(grants.stream().noneMatch(g -> g.action() == Permission.Action.APPROVAL_DECIDE_OWN || g.action() == Permission.Action.CERTIFICATE_READ_CONTENT || g.action() == Permission.Action.CERTIFICATE_DOWNLOAD));
                }
                org.junit.jupiter.api.Assertions.assertEquals(1, realm.directGrants("trusted-proxy").size());
            }
            PkiAdminBootstrap.provisionStatusAccess(configuration, "bootstrap-admin", "bootstrap-approver", "trusted-proxy");
        }
        try (var realm = ServerRealmContext.open(configuration.realm(), PkiSessionRuntimeDependencies.none())) {
            realm.setPrincipalEnabled("bootstrap-approver", false, "bootstrap-admin");
        }
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.provisionStatusAccess(configuration, "bootstrap-admin", "bootstrap-approver", "trusted-proxy"));
        var changed = AdministrativeWorkflowFixture.configuration(Files.createDirectory(directory.resolve("revoked-capability")), false);
        PkiCertificateAccessTest.legacy(changed);
        try(var realm=ServerRealmContext.open(changed.realm(),PkiSessionRuntimeDependencies.none())) {
            var scope=new Permission.Scope(changed.realm().realmId(),java.util.Optional.empty(),java.util.Optional.empty(),java.util.Optional.empty());
            realm.grant(new Permission.Grant("bootstrap.approver.status-download","bootstrap-approver",Permission.Effect.ALLOW,
                    Permission.Action.CRL_DOWNLOAD,Permission.ResourceType.STATUS_OBJECT,scope,Permission.Relationship.ANY,
                    Permission.DataView.CONTENT_FULL,java.util.Set.of(),java.util.Optional.empty(),false),"system");
        }
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.provisionStatusAccess(changed,"bootstrap-admin","bootstrap-approver","trusted-proxy"));
        try(var realm=ServerRealmContext.open(changed.realm(),PkiSessionRuntimeDependencies.none())) {
            org.junit.jupiter.api.Assertions.assertTrue(realm.directGrants("bootstrap-admin").stream().noneMatch(grant -> grant.action()==Permission.Action.CRL_DOWNLOAD && grant.dataView()==Permission.DataView.CONTENT_FULL),"preflight failure partially granted the earlier principal");
        }
        Path store = Path.of(configuration.realm().pkiSessionConfiguration().store().require("root"));
        Files.move(store, store.resolveSibling("saved-store")); Files.createDirectory(store);
        org.junit.jupiter.api.Assertions.assertThrows(IllegalArgumentException.class, () -> PkiAdminBootstrap.provisionStatusAccess(configuration, "bootstrap-admin", "bootstrap-approver", "trusted-proxy"));
        org.junit.jupiter.api.Assertions.assertFalse(Files.exists(store.resolve("VERSION")));
    }
}
