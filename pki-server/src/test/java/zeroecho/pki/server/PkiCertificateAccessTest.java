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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Comparator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;

/** Real initial-state migration tests, including old numbered grants and fail-closed incomplete stores. */
class PkiCertificateAccessTest {
    @TempDir Path directory;
    @Test void provisionsOnlyExactContentCapabilitiesIdempotentlyWithoutRootApproval() throws Exception { exercise(directory); }
    static void exercise(Path root)throws Exception {
        var configuration=AdministrativeWorkflowFixture.configuration(root,false);
        legacy(configuration);
        Path store=Path.of(configuration.realm().pkiSessionConfiguration().store().require("root"));
        byte[] version=Files.readAllBytes(store.resolve("VERSION"));
        PkiAdminBootstrap.provisionCertificateAccess(configuration,"bootstrap-admin","bootstrap-approver","trusted-proxy");
        try(var realm=ServerRealmContext.open(configuration.realm(),PkiSessionRuntimeDependencies.none())) {
            for(String principal:List.of("bootstrap-admin","bootstrap-approver")) {
                var content=realm.directGrants(principal).stream().filter(grant -> grant.action()==Permission.Action.CERTIFICATE_READ_CONTENT||grant.action()==Permission.Action.CERTIFICATE_DOWNLOAD).toList();
                check(content.size()==2&&content.stream().allMatch(grant -> grant.enabled()&&grant.dataView()==Permission.DataView.CONTENT_FULL),"wrong additive capabilities");
            }
            check(realm.directGrants("bootstrap-admin").stream().noneMatch(grant -> grant.action()==Permission.Action.APPROVAL_DECIDE_OWN),"content migration assigned root approval");
            check(realm.directGrants("trusted-proxy").size()==1,"proxy broadened");
        }
        var before=snapshot(configuration);
        PkiAdminBootstrap.provisionCertificateAccess(configuration,"bootstrap-admin","bootstrap-approver","trusted-proxy");
        check(before.equals(snapshot(configuration)),"idempotent migration changed capabilities");
        check(java.util.Arrays.equals(version,Files.readAllBytes(store.resolve("VERSION"))),"PKI identity changed");
        PkiAdminBootstrap.provisionRootAdmin(configuration,"bootstrap-admin","bootstrap-approver","trusted-proxy");
        PkiAdminBootstrap.provisionCertificateAccess(configuration,"bootstrap-admin","bootstrap-approver","trusted-proxy");
        try(var realm=ServerRealmContext.open(configuration.realm(),PkiSessionRuntimeDependencies.none())) {
            check(realm.directGrants("bootstrap-admin").stream().filter(grant -> grant.action()==Permission.Action.APPROVAL_DECIDE_OWN).count()==1,"root compatibility failed");
            realm.setPrincipalEnabled("bootstrap-approver",false,"bootstrap-admin");
        }
        before=snapshot(configuration);
        try {PkiAdminBootstrap.provisionCertificateAccess(configuration,"bootstrap-admin","bootstrap-approver","trusted-proxy");throw new AssertionError("disabled initial user restored");}catch(IllegalArgumentException expected) { }
        check(before.equals(snapshot(configuration)),"refusal changed capabilities");
        Path saved=store.resolveSibling("saved-pki");Files.move(store,saved);Files.createDirectory(store);
        try {PkiAdminBootstrap.provisionCertificateAccess(configuration,"bootstrap-admin","bootstrap-approver","trusted-proxy");throw new AssertionError("empty PKI store initialized");}catch(IllegalArgumentException expected) { }
        check(Files.notExists(store.resolve("VERSION")),"refusal initialized PKI identity");
        for(boolean revokedContent:new boolean[]{false,true}) {
            Path changed=Files.createDirectory(root.resolve(revokedContent?"revoked-content":"changed-baseline"));
            var config=AdministrativeWorkflowFixture.configuration(changed,false);legacy(config);
            try(var realm=ServerRealmContext.open(config.realm(),PkiSessionRuntimeDependencies.none())) {
                if(revokedContent) {
                    var scope=new Permission.Scope(config.realm().realmId(),Optional.empty(),Optional.empty(),Optional.empty());
                    var denied=new Permission.Grant("bootstrap.approver.certificate-download","bootstrap-approver",Permission.Effect.ALLOW,
                            Permission.Action.CERTIFICATE_DOWNLOAD,Permission.ResourceType.CERTIFICATE,scope,Permission.Relationship.ANY,Permission.DataView.CONTENT_FULL,java.util.Set.of(),Optional.empty(),false);
                    realm.grant(denied,"system");
                } else {
                    var control=AdministrativeWorkflowFixture.control(realm);var grant=control.requireGrant("bootstrap.approver.0");
                    control.replaceGrant(grant,new Permission.Grant(grant.grantId(),grant.principalId(),grant.effect(),grant.action(),grant.resourceType(),grant.scope(),grant.relationship(),grant.dataView(),grant.conditions(),grant.expiresAt(),false));
                }
            }
            var unchanged=snapshot(config);
            try {PkiAdminBootstrap.provisionCertificateAccess(config,"bootstrap-admin","bootstrap-approver","trusted-proxy");throw new AssertionError("revoked or changed permission restored");}catch(IllegalArgumentException expected) { }
            check(unchanged.equals(snapshot(config)),"validation wrote earlier initial user's capabilities before rejecting later user");
            check(snapshot(config).get("bootstrap-admin").stream().noneMatch(grant -> grant.action()==Permission.Action.CERTIFICATE_DOWNLOAD),"partial migration before preflight completed");
        }
        System.out.println("PASS legacy numbered grants preserved; exact content-only pair migration; idempotent; root-own independent; disabled and uninitialized states refused");
    }
    private static Map<String,List<Permission.Grant>> snapshot(PkiServerConfiguration configuration)throws Exception {
        try(var realm=ServerRealmContext.open(configuration.realm(),PkiSessionRuntimeDependencies.none())) {
            return Map.of("bootstrap-admin",realm.directGrants("bootstrap-admin"),"bootstrap-approver",realm.directGrants("bootstrap-approver"),"trusted-proxy",realm.directGrants("trusted-proxy"));
        }
    }
    static void legacy(PkiServerConfiguration configuration)throws Exception {
        var scope=new Permission.Scope(configuration.realm().realmId(),Optional.empty(),Optional.empty(),Optional.empty());
        try(var realm=ServerRealmContext.open(configuration.realm(),PkiSessionRuntimeDependencies.none())) {
            realm.createPrincipal(new SecurityPrincipal("trusted-proxy",SecurityPrincipal.Type.SERVICE,"Initial reverse proxy",Optional.empty(),Map.of(),true),"system");
            realm.grant(grant("bootstrap.proxy-forward","trusted-proxy",Permission.Action.FORWARD_AUTHENTICATED_CLIENT_IDENTITY,Permission.ResourceType.REALM,scope,Permission.DataView.METADATA_REDACTED),"system");
            var original=new OperationSecurityDescriptors().descriptors().values().stream().filter(value -> !value.operationId().equals(PkiOperation.ListCredentials.NAME)).sorted(Comparator.comparing(OperationSecurityDescriptors.Descriptor::operationId)).toList();
            check(original.size()==150,"Legacy catalog changed; review historical grants explicitly");
            for(String principal:List.of("bootstrap-admin","bootstrap-approver")) {
                realm.createPrincipal(new SecurityPrincipal(principal,SecurityPrincipal.Type.USER,principal,Optional.empty(),Map.of(),true),"system");
                String prefix=principal.equals("bootstrap-admin")?"bootstrap.admin.":"bootstrap.approver.";int index=0;
                for(var descriptor:original)realm.grant(grant(prefix+index++,principal,descriptor.action(),descriptor.resourceType(),scope,descriptor.dataView()),"system");
                realm.grant(grant(prefix+"realm-read",principal,Permission.Action.REALM_READ,Permission.ResourceType.REALM,scope,Permission.DataView.METADATA_REDACTED),"system");
            }
        }
        Path control=configuration.realm().controlLogPath();Files.createFile(control.resolveSibling(control.getFileName()+".admin-bootstrap-started"));
    }
    private static Permission.Grant grant(String id,String principal,Permission.Action action,Permission.ResourceType type,Permission.Scope scope,Permission.DataView view) {
        return new Permission.Grant(id,principal,Permission.Effect.ALLOW,action,type,scope,Permission.Relationship.ANY,view,java.util.Set.of(),Optional.empty(),true);
    }
    private static void check(boolean result,String message) {if(!result)throw new AssertionError(message);}
    /** Runs the real migration fixture without asserting that external JUnit dependencies executed. */
    public static void main(String[] args)throws Exception {exercise(Files.createTempDirectory("zeroecho-certificate-access-"));}
}
