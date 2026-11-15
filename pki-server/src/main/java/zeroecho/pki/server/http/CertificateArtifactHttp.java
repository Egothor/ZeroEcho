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

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.ServerRealmContext;

/** Authenticated, disclosure-independent public-certificate retrieval with exact live content permission checks. */
final class CertificateArtifactHttp {
    private static final int MAXIMUM_BYTES=4_194_304;
    private final ServerRealmContext realm;
    CertificateArtifactHttp(ServerRealmContext realm) { this.realm=java.util.Objects.requireNonNull(realm,"realm"); }

    /** Resolves trusted metadata first and opens bytes only after both full-content permissions succeed. */
    HttpResponses.Response respond(String rawPath,String query,String principal,String trace,CancellationSignal cancellation)throws IOException {
        try {
            String[] path=rawPath.split("/",-1);
            boolean authority=path.length==6&&path[3].equals("authorities")&&path[5].equals("certificate");
            boolean artifact=(path.length==5||path.length==6&&path[5].equals("content"))&&path[3].equals("certificate-artifacts");
            if(!authority&&!artifact)throw new SecurityException("Certificate unavailable");
            var repository=realm.session().repository();
            PkiId credentialId;
            if(authority) {
                PkiId authorityId=new PkiId(HttpPathIdentifier.decode(path[4]));
                var authorityResource=new Permission.Resource(Permission.ResourceType.AUTHORITY,
                        new Permission.Scope(realm.configuration().realmId(),Optional.of(authorityId),Optional.empty(),Optional.empty()),
                        Optional.of(authorityId),Optional.empty());
                if(!allowed(principal,Permission.Action.AUTHORITY_READ,authorityResource,Permission.DataView.METADATA_REDACTED,trace))throw new SecurityException("Certificate unavailable");
                var ca=repository.authority(authorityId).orElseThrow();
                credentialId=repository.issuer(ca.currentIssuanceIssuerId()).orElseThrow().credentialId();
            } else credentialId=new PkiId(HttpPathIdentifier.decode(path[4]));
            var credential=repository.credential(credentialId).orElseThrow();
            var coordinates=realm.session().resourceScopes().credentialReadScope(credentialId).orElseThrow();
            var resource=new Permission.Resource(Permission.ResourceType.CERTIFICATE,
                    new Permission.Scope(realm.configuration().realmId(),Optional.of(coordinates.authorityId()),Optional.of(credential.issuerRef().issuerId()),Optional.of(coordinates.profileId())),
                    Optional.of(credentialId),Optional.empty());
            if(!allowed(principal,Permission.Action.CERTIFICATE_READ_METADATA,resource,Permission.DataView.METADATA_REDACTED,trace))throw new SecurityException("Certificate unavailable");
            boolean content=allowed(principal,Permission.Action.CERTIFICATE_READ_CONTENT,resource,Permission.DataView.CONTENT_FULL,trace)
                    &&allowed(principal,Permission.Action.CERTIFICATE_DOWNLOAD,resource,Permission.DataView.CONTENT_FULL,trace);
            boolean download=artifact&&path.length==6;
            var representations=content?repository.credentialRepresentations(credentialId):List.<zeroecho.pki.spi.framework.CredentialFramework.CredentialRepresentation>of();
            if(download) {
                if(!content||query==null||!query.matches("representation=[a-z][a-z0-9-]{0,31}"))throw new SecurityException("Certificate unavailable");
                String selected=query.substring("representation=".length());
                var representation=representations.stream().filter(value -> value.id().equals(selected)).findFirst().orElseThrow();
                cancellation.throwIfCancelled();
                try(var lease=repository.openCredential(credentialId,selected,cancellation);var stream=lease.openStream()) {
                    if(lease.length()>MAXIMUM_BYTES)throw new IOException("Certificate exceeds bounded download size");
                    byte[] bytes=stream.readNBytes(MAXIMUM_BYTES+1);
                    cancellation.throwIfCancelled();
                    if(bytes.length!=lease.length()||bytes.length>MAXIMUM_BYTES)throw new IOException("Certificate content length differs");
                    realm.auditTransport("CERTIFICATE_DOWNLOAD",principal,Map.of("credentialId",credentialId.value(),"representation",selected));
                    return HttpResponses.attachment(bytes,representation.mediaType(),fileName(credentialId,representation.fileExtension()));
                }
            }
            if(query!=null)throw new SecurityException("Certificate unavailable");
            Map<String,PkiOperationValue> fields=new LinkedHashMap<>();
            fields.put("issuerId",text(credential.issuerRef().issuerId().value()));
            fields.put("credentialId",text(credentialId.value()));fields.put("authorityId",text(coordinates.authorityId().value()));fields.put("formatId",text(credential.formatId().value()));
            fields.put("representations",new PkiOperationValue.ListValue(representations.stream().<PkiOperationValue>map(value -> new PkiOperationValue.ObjectValue(Map.of(
                    "id",text(value.id()),"label",text(value.label()),"mediaType",text(value.mediaType()),"fileName",text(fileName(credentialId,value.fileExtension())),
                    "href",text("/admin/v1/certificate-artifacts/"+java.net.URLEncoder.encode(credentialId.value(),java.nio.charset.StandardCharsets.UTF_8)+"/content?representation="+value.id())))).toList()));
            return HttpResponses.success(trace,"certificate.artifact.inspect",new PkiOperationValue.ObjectValue(Map.of("value",new PkiOperationValue.ObjectValue(fields))));
        } catch(SecurityException|IllegalArgumentException|java.util.NoSuchElementException unavailable) {
            return HttpResponses.failure(404,trace,"certificate.artifact.inspect","NOT_FOUND","CERTIFICATE_UNAVAILABLE","CERTIFICATE_UNAVAILABLE",false,false);
        }
    }
    private boolean allowed(String principal,Permission.Action action,Permission.Resource resource,Permission.DataView view,String trace) {
        return realm.gateway().authorizeControl(principal,action,resource,view,Permission.Context.empty(),trace).allowed();
    }
    private static String fileName(PkiId id,String extension) {
        try {
            String digest=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(id.value().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
            return "certificate-"+digest.substring(0,16)+"."+extension;
        } catch(java.security.NoSuchAlgorithmException impossible) { throw new IllegalStateException("SHA-256 unavailable",impossible); }
    }
    private static PkiOperationValue.Text text(String value) { return new PkiOperationValue.Text(value); }
}
