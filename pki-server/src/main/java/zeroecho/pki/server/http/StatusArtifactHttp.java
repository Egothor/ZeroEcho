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

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.Permission;
import zeroecho.pki.server.ServerRealmContext;

/**
 * Exact stored status-object metadata and bounded streaming downloads under independent full-content authority.
 */
final class StatusArtifactHttp {
    private final ServerRealmContext realm;
    /**
     * Binds status-artifact transport projection to one borrowed realm context.
     *
     * @param realm realm-owned authorization and repository services
     * @throws NullPointerException if realm is null
     */
    StatusArtifactHttp(ServerRealmContext realm){this.realm=java.util.Objects.requireNonNull(realm,"realm");}
    /**
     * Projects authorized status metadata or streams an exact retained representation.
     *
     * <p>Downloads are written directly to the exchange and verified against the retained
     * length and SHA-256. Metadata and failure responses are returned for the caller to send.</p>
     *
     * @param exchange active HTTP exchange with the raw status-artifact route
     * @param principal authenticated principal identity
     * @param trace transport correlation identity used for response headers and audit
     * @param cancellation exact transport cancellation signal
     * @return response to send, or null when a download was already streamed
     * @throws IOException if repository access, streaming or integrity verification fails
     */
    HttpResponses.Response respond(HttpExchange exchange,String principal,String trace,CancellationSignal cancellation)throws IOException {
        try {
            String[] path=exchange.getRequestURI().getRawPath().split("/",-1);
            boolean download=path.length==6&&path[5].equals("content");
            if(!(path.length==5||download)||!path[3].equals("status-artifacts"))throw new SecurityException("Status object unavailable");
            PkiId id=new PkiId(HttpPathIdentifier.decode(path[4]));
            var repository=realm.session().repository();var object=repository.statusObject(id).orElseThrow();
            var resource=new Permission.Resource(Permission.ResourceType.STATUS_OBJECT,
                    new Permission.Scope(realm.configuration().realmId(),Optional.of(object.issuerCaId()),Optional.empty(),Optional.empty()),Optional.of(id),Optional.empty());
            Permission.DataView view=download?Permission.DataView.CONTENT_FULL:Permission.DataView.METADATA_REDACTED;
            if(!realm.gateway().authorizeControl(principal,Permission.Action.CRL_DOWNLOAD,resource,view,Permission.Context.empty(),trace).allowed())throw new SecurityException("Status object unavailable");
            boolean full=download||realm.gateway().authorizeControl(principal,Permission.Action.CRL_DOWNLOAD,resource,Permission.DataView.CONTENT_FULL,Permission.Context.empty(),trace).allowed();
            var representations=full?repository.statusRepresentations(id):java.util.List.<zeroecho.pki.spi.framework.CredentialFramework.CredentialRepresentation>of();
            String query=exchange.getRequestURI().getRawQuery();
            if(download) {
                if(query==null||!query.matches("representation=[a-z][a-z0-9-]{0,31}"))throw new SecurityException("Status representation unavailable");
                String selected=query.substring("representation=".length());
                var representation=representations.stream().filter(value -> value.id().equals(selected)).findFirst().orElseThrow();
                try(var lease=repository.openStatusObject(id,selected,cancellation);var input=lease.openStream()) {
                    cancellation.throwIfCancelled();
                    var headers=exchange.getResponseHeaders();headers.set("Content-Type",representation.mediaType());
                    headers.set("Content-Disposition","attachment; filename=\""+fileName(id,representation.fileExtension())+"\"");
                    headers.set("Cache-Control","no-store");headers.set("X-Content-Type-Options","nosniff");headers.set("Referrer-Policy","no-referrer");headers.set(RequestIds.HEADER,trace);
                    headers.set("Content-Digest","sha-256=:"+java.util.Base64.getEncoder().encodeToString(java.util.HexFormat.of().parseHex(lease.sha256()))+":");
                    var digest=sha256();long written=0;byte[] buffer=new byte[16*1024];
                    exchange.sendResponseHeaders(200,lease.length());
                    try(var output=exchange.getResponseBody()) {
                        int read;while((read=input.read(buffer))!=-1){cancellation.throwIfCancelled();if(read>lease.length()-written)throw new IOException("Status length differs");output.write(buffer,0,read);written+=read;digest.update(buffer,0,read);}
                        cancellation.throwIfCancelled();
                        if(written!=lease.length()||!java.util.HexFormat.of().formatHex(digest.digest()).equals(lease.sha256()))throw new IOException("Status stream integrity differs");
                    }
                    realm.auditTransport("STATUS_DOWNLOAD",principal,Map.of("statusObjectId",id.value(),"representation",selected,"bytes",Long.toString(written)));
                }
                return null;
            }
            if(query!=null)throw new SecurityException("Status object unavailable");
            var metadata=new LinkedHashMap<String,PkiOperationValue>();metadata.put("statusObjectId",text(id.value()));metadata.put("authorityId",text(object.issuerCaId().value()));
            metadata.put("formatId",text(object.formatId().value()));metadata.put("type",text(object.type().name()));
            metadata.put("representations",new PkiOperationValue.ListValue(representations.stream().<PkiOperationValue>map(value -> new PkiOperationValue.ObjectValue(Map.of(
                    "id",text(value.id()),"label",text(value.label()),"mediaType",text(value.mediaType()),"fileName",text(fileName(id,value.fileExtension())),
                    "href",text("/admin/v1/status-artifacts/"+java.net.URLEncoder.encode(id.value(),java.nio.charset.StandardCharsets.UTF_8)+"/content?representation="+value.id())))).toList()));
            return HttpResponses.success(trace,"status.artifact.inspect",new PkiOperationValue.ObjectValue(Map.of("value",new PkiOperationValue.ObjectValue(metadata))));
        } catch(SecurityException|IllegalArgumentException|java.util.NoSuchElementException unavailable) {
            if(exchange.getResponseCode()!=-1){exchange.close();return null;}
            return HttpResponses.failure(404,trace,"status.artifact.inspect","NOT_FOUND","STATUS_UNAVAILABLE","STATUS_UNAVAILABLE",false,false);
        } catch(IOException failure) {
            realm.auditTransport("STATUS_DOWNLOAD_FAILED",principal,Map.of("request",trace));if(exchange.getResponseCode()!=-1)exchange.close();throw failure;
        }
    }
    private static java.security.MessageDigest sha256(){try{return java.security.MessageDigest.getInstance("SHA-256");}catch(java.security.NoSuchAlgorithmException impossible){throw new IllegalStateException("SHA-256 unavailable",impossible);}}
    private static String fileName(PkiId id,String extension){return "status-"+java.util.HexFormat.of().formatHex(sha256().digest(id.value().getBytes(java.nio.charset.StandardCharsets.UTF_8))).substring(0,16)+"."+extension;}
    private static PkiOperationValue.Text text(String value){return new PkiOperationValue.Text(value);}
}
