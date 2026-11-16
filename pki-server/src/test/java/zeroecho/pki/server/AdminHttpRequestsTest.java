/*
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
 */
package zeroecho.pki.server;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.LockSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.TestTlsProvider;

/**
 * Native TLS HTTP coverage for durable administrative request admission and observation.
 */
class AdminHttpRequestsTest {
    /**
     * Exercises native TLS administrative submission with retained exact target and continuation after separate approval.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void nativeHttpSubmissionRetainsTargetAndContinuesAfterIndependentApproval(@TempDir Path directory) throws Exception {
        exercise(directory);
    }

    /**
     * Runs the real retained administrative-request HTTP workflow against an isolated loopback server.
     *
     * @param directory isolated fixture control, PKI and TLS storage root
     * @throws Exception if server setup, request/approval workflow, restart or cleanup fails
     */
    static void exercise(Path directory) throws Exception {
        var tls = HttpServerTestSupport.tls();
        var transport = HttpServerTestSupport.configuration(directory.resolve("transport"), tls.clientCertificate());
        var unsigned = AdministrativeWorkflowFixture.configuration(directory, false);
        PkiAdminBootstrap.bootstrap(unsigned, "bootstrap-admin", "bootstrap-approver", "trusted-proxy");
        var domain = AdministrativeWorkflowFixture.configuration(directory, true);
        var authentication = new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(mapping("admin", "bootstrap-admin", tls.clientCertificate()),
                        mapping("outsider", "outsider", tls.proxyCertificate())), List.of(), List.of(),
                java.util.Set.of(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0);
        var config = new PkiServerConfiguration(domain.version(), domain.serverName(), domain.realm(),
                transport.listener(), authentication, transport.execution(), transport.runtime());
        Path keys = directory.resolve("keyring");
        Files.createDirectory(keys, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try (var password = new KeyringPassword(AdministrativeWorkflowFixture.PASSWORD.toCharArray());
                var ring = KeyringStore.create(keys.resolve("signing.zek"), password)) {
            var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(3072);
            var pair = generator.generateKeyPair();
            ring.putPrivate("root.prv", "RSA", pair.getPrivate()); ring.putPublic("root.pub", "RSA", pair.getPublic());
            var intermediate=generator.generateKeyPair();ring.putPrivate("intermediate.prv","RSA",intermediate.getPrivate());ring.putPublic("intermediate.pub","RSA",intermediate.getPublic());
        }
        var dependencies = PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                () -> new KeyringPassword(AdministrativeWorkflowFixture.PASSWORD.toCharArray()));
        try (var realm = ServerRealmContext.open(config.realm(), dependencies)) {
            realm.createPrincipal(ServerTestSupport.principal("outsider"), "system");
            for (var profile : BuiltInCertificateProfileCatalog.load(AdminHttpRequestsTest.class.getClassLoader())) {
                if (java.util.Set.of("root-ca","server-tls","intermediate-ca").contains(profile.definition().profileId())) {
                    realm.session().profiles().importBuiltIn(profile);
                    realm.session().profiles().activateProfile(profile.definition().profileId(), profile.definition().profileVersion());
                }
            }
        }
        try (var admin = HttpClient.newBuilder().sslContext(tls.clientContext()).build();
                var outsider = HttpClient.newBuilder().sslContext(tls.proxyContext()).build();
                var anonymous = HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
                var server = PkiHttpsServer.start(config, dependencies, Clock.systemUTC(),
                        HttpServerTestSupport.random(), TestTlsProvider.class.getClassLoader())) {
            String base = "https://localhost:" + server.address().getPort() + "/admin/v1/requests";
            check(get(admin, "https://localhost:" + server.address().getPort() + "/admin/v1/hybrid-sdk/v1").statusCode() == 404,
                    "SDK capability was advertised without listener opt-in");
            var capabilities = get(admin, "https://localhost:" + server.address().getPort() + "/admin/v1/realm");
            check(capabilities.statusCode()==200 && capabilities.body().contains("\"publicRepository\":{\"available\":false,\"authorityListAvailable\":false}"),
                    "disabled public repository was not authoritatively advertised: "+capabilities.body());
            var advertised=get(admin,"https://localhost:"+server.address().getPort()+"/admin/v1/operations");
            for(String unavailable:List.of("acme.account.list","acme.directory.list","enrollment.request.list","est.endpoint.list")) {
                check(!server.realm().gateway().operationAvailable(unavailable),"absent service reported available: "+unavailable);
                check(!advertised.body().contains("\"operationId\":\""+unavailable+"\""),"absent service discovered: "+unavailable);
                var execution=post(admin,"https://localhost:"+server.address().getPort()+"/admin/v1/operations/"+unavailable,"{\"version\":1,\"arguments\":{\"offset\":0,\"limit\":1}}","application/json");
                check(execution.statusCode()==404&&execution.body().contains("OPERATION_NOT_FOUND"),"absent protocol did not fail closed before execution: "+unavailable+execution.body());
            }
            check(server.realm().gateway().operationAvailable("enrollment.profile.list"),"functional enrollment profiles hidden");
            check(server.realm().gateway().operationAvailable("ocsp.responder.list"),"functional OCSP hidden");
            try {
                check(get(anonymous, base).statusCode() >= 400, "anonymous request access accepted");
            } catch (java.io.IOException expected) { /* Mutual TLS rejects before HTTP. */ }
            check(post(admin, base, "{}", "text/plain").statusCode() == 415, "media type accepted");
            check(post(admin, base, "{}", "application/json").statusCode() == 400, "missing fields accepted");
            check(post(admin, base, body("bad-version", "CN=Valid").replace("\"version\":1", "\"version\":2"),
                    "application/json").statusCode() == 400, "unsupported version accepted");
            check(post(admin, base, body("bad-field", "CN=Valid").replace("\"arguments\":", "\"extra\":true,\"arguments\":"),
                    "application/json").statusCode() == 400, "unknown field accepted");
            check(post(admin, base, body("bad-deadline", "CN=Valid").replace("\"arguments\":", "\"deadline\":\"PT0S\",\"arguments\":"),
                    "application/json").statusCode() == 400, "zero deadline accepted");
            check(post(admin, base, body("bad", "Bare Root"), "application/json").statusCode() == 400, "bad DN accepted");
            var invalid = post(admin, base, body("bad", "Bare Root"), "application/json");
            check(invalid.body().contains("CA_SUBJECT_INVALID"), "missing safe syntax diagnostic: " + invalid.body());
            try { server.realm().approvals().requireCurrent("admin-request.bad"); throw new AssertionError("bad DN created approval"); }
            catch (IllegalArgumentException expected) { /* Nothing was persisted. */ }
            check(get(admin, base + "/bad").statusCode() == 404, "bad request was retained");
            var accepted = post(admin, base, body("http-once", "CN=HTTP Root"), "application/json");
            check(accepted.statusCode() == 202 && accepted.body().contains("PENDING")
                    && accepted.body().contains("administrative.request.submit"), "no 202 ticket: " + accepted.body());
            check(post(admin, base, body("http-once", "CN=HTTP Root"), "application/json").statusCode() == 202,
                    "duplicate exact target did not return retained request");
            check(post(admin, base, body("http-once", "CN=Different Root"), "application/json").statusCode() == 409,
                    "duplicate ID changed target");
            check(get(outsider, base + "/http-once").statusCode() == 404, "nonowner read retained request");
            check(!get(outsider, base).body().contains("http-once"), "nonowner list leaked retained request");
            check(get(admin, base + "?limit=1&offset=0").body().contains("http-once"), "owner list omitted pending request");
            check(get(admin, base + "?limit=0").statusCode() == 400, "invalid page accepted");
            check(get(admin, base + "?limit=1&limit=2").statusCode() == 400, "duplicate query accepted");
            var retained = server.realm().administrativeRequests().inspect("http-once", "bootstrap-admin");
            check(retained.state() == AdministrativeRequest.State.WAITING_APPROVAL, "not waiting for approval");
            check(get(admin, base + "/http-once").body().contains("CN=HTTP Root"), "exact subject absent from detail");
            server.realm().approvals().decide(retained.approvalId().orElseThrow(), "bootstrap-approver",
                    ApprovalService.Choice.APPROVE, "Independent approval in another administrative session");
            long until = System.nanoTime() + Duration.ofSeconds(30).toNanos();
            while (!(retained = server.realm().administrativeRequests().inspect("http-once", "bootstrap-admin")).terminal()) {
                if (System.nanoTime() >= until) throw new AssertionError("HTTP request never completed");
                LockSupport.parkNanos(Duration.ofMillis(20).toNanos());
            }
            check(retained.state() == AdministrativeRequest.State.SUCCEEDED && retained.result().isPresent(),
                    "approved request failed: " + retained.state() + retained.failureCode());
            var observed = get(admin, base + "/http-once");
            check(observed.statusCode() == 200 && observed.body().contains("SUCCEEDED") && observed.body().contains("signingOperationId"),
                    "HTTP final projection omitted signing receipt/result: " + observed.body());
            check(server.realm().session().repository().authorities(Optional.empty(), 10).size() == 1, "approval did not create exactly one CA");
            artifacts(server,admin,outsider,base);
            try (var bridge = new FrontendTestBridge(directory, server.address(), tls);
                    var browser = HttpClient.newHttpClient()) {
                String requestRoute = bridge.baseUri() + "/admin/v1/requests";
                String firstPage=get(browser, requestRoute + "?offset=0&limit=1").body();
                check(firstPage.contains("\"requests\":")&&firstPage.contains("\"nextOffset\":1")&&firstPage.contains("\"hasMore\":true"),
                        "bridge omitted bounded pagination query: "+firstPage);
                check(get(browser, requestRoute + "/http-once").body().contains("SUCCEEDED"), "bridge blocked detail");
                check(post(browser, requestRoute, body("http-once", "CN=HTTP Root"), "application/json").statusCode() == 202,
                        "bridge blocked durable submission route");
                var put = browser.send(HttpRequest.newBuilder(URI.create(requestRoute)).PUT(HttpRequest.BodyPublishers.noBody()).build(),
                        HttpResponse.BodyHandlers.ofString());
                check(put.statusCode() == 405, "bridge allowed unsupported request mutation");
            }
            System.out.println("PASS native TLS HTTP: strict admission; zero approval on invalid DN; retained 202/idempotency/conflict; ownership/list; approval auto-creates exactly one CA");
        }
        publicContract(config,dependencies,tls,directory);
    }

    private static void publicContract(PkiServerConfiguration source,PkiSessionRuntimeDependencies dependencies,HttpServerTestSupport.Fixture tls,Path directory)throws Exception {
        var proxy=HttpServerTestSupport.proxyConfiguration(directory.resolve("proxy-settings"),tls,ForwardedCertificateFormat.RFC9440).authentication();
        var authentication=new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY,List.of(),
                List.of(mapping("transport","trusted-proxy",tls.proxyCertificate())),List.of(mapping("forwarded","bootstrap-admin",tls.forwardedCertificate())),
                java.util.Set.of("trusted-proxy"),proxy.forwardedCertificateFormat(),proxy.forwardedCertificateHeaderName(),proxy.forwardedCertificateChainHeaderName(),proxy.administrativeClientTrust(),proxy.maximumForwardedCertificateBytes(),proxy.maximumForwardedChainBytes());
        for(boolean exposed:new boolean[]{false,true}) {
            var listener=new PkiServerConfiguration.PublicListener(java.net.InetAddress.getLoopbackAddress(),0,Optional.of(new zeroecho.pki.spi.ProviderConfig("test-tls",java.util.Map.of())),false,
                    authentication,16384,65536,source.execution(),java.time.Duration.ofSeconds(10),java.time.Duration.ZERO,java.time.Duration.ZERO,exposed,Optional.of("/public/v1"));
            var config=new PkiServerConfiguration(source.version(),source.serverName(),source.realm(),source.listener(),source.authentication(),source.execution(),source.runtime(),Optional.of(listener),Optional.empty());
            try(var client=HttpClient.newBuilder().sslContext(tls.clientContext()).build();var transport=HttpClient.newBuilder().sslContext(tls.proxyContext()).build();
                    var server=PkiHttpsServer.start(config,dependencies,Clock.systemUTC(),HttpServerTestSupport.random(),TestTlsProvider.class.getClassLoader())) {
                String admin="https://localhost:"+server.address().getPort();
                var capabilities=get(client,admin+"/admin/v1/realm");
                check(capabilities.body().contains("\"publicRepository\":{\"available\":true,\"authorityListAvailable\":"+exposed+",\"basePath\":\"/public/v1\"}"),"published route capability/list policy differs: "+capabilities.body());
                var ca=server.realm().session().repository().authorities(Optional.empty(),10).getFirst();
                String publicBase="https://localhost:"+server.publicAddress().orElseThrow().getPort()+"/public/v1";
                var listing=get(transport,publicBase+"/authorities?limit=1&after="+encoded(ca.caId().value()));
                check(listing.statusCode()==(exposed?200:404),"public list binding/encoded cursor failed: "+listing.statusCode()+listing.body());
                var privateCertificate=get(transport,publicBase+"/authorities/"+encoded(ca.caId().value())+"/issuers/"+encoded(ca.currentIssuanceIssuerId().value())+"/certificate");
                check(privateCertificate.statusCode()==404,"public binding widened private certificate disclosure");
            }
        }
        System.out.println("PASS actual TLS explicit public binding, list capability true/false, encoded-colon cursor and private-content disclosure unchanged");
    }

    private static void artifacts(PkiHttpsServer server,HttpClient admin,HttpClient outsider,String requests)throws Exception {
        var realm=server.realm();var repository=realm.session().repository();
        var ca=repository.authorities(Optional.empty(),10).getFirst();
        var rootCredential=repository.issuer(ca.currentIssuanceIssuerId()).orElseThrow().credentialId();
        makePrivate(realm,rootCredential,DisclosureService.ObjectType.CA_CERTIFICATE);
        String authorityEnvelope="{\"version\":1,\"authorityId\":\""+ca.caId().value()+"\",\"arguments\":{\"credentialId\":\""+rootCredential.value()+"\"}}";
        String administrative="https://localhost:"+server.address().getPort()+"/admin/v1/operations/";
        check(post(admin,administrative+"credential.inspect",authorityEnvelope,"application/json").statusCode()==200,"CA metadata read scope unavailable");
        String revokeEnvelope=authorityEnvelope.replace("\"credentialId\":", "\"reason\":\"KEY_COMPROMISE\",\"justification\":\"Disposable scope regression\",\"credentialId\":");
        check(post(admin,administrative+"credential.revoke",revokeEnvelope,"application/json").statusCode()==403,"CA read support broadened permanent revocation authority");
        check(realm.session().revocations().get(rootCredential).isEmpty(),"denied administrative CA revocation reached domain mutation");
        String origin="https://localhost:"+server.address().getPort();
        var current=get(admin,origin+"/admin/v1/authorities/"+encoded(ca.caId().value())+"/certificate");
        check(current.statusCode()==200&&current.body().contains(rootCredential.value()),"current CA certificate was not resolved");
        certificateBytes(server,admin,rootCredential);
        String content=origin+"/admin/v1/certificate-artifacts/"+encoded(rootCredential.value())+"/content?representation=original";
        check(binaryGet(outsider,content).statusCode()==404,"content without explicit permission accepted");
        var scope=new Permission.Scope(realm.configuration().realmId(),Optional.of(ca.caId()),Optional.empty(),Optional.empty());
        realm.grant(ServerTestSupport.grant("outsider.metadata","outsider",Permission.Effect.ALLOW,Permission.Action.CERTIFICATE_READ_METADATA,Permission.ResourceType.CERTIFICATE,scope,Permission.Relationship.ANY,Permission.DataView.METADATA_REDACTED),"system");
        var metadata=get(outsider,origin+"/admin/v1/certificate-artifacts/"+encoded(rootCredential.value()));
        check(metadata.statusCode()==200&&metadata.body().contains("\"representations\":[]"),"metadata-only principal got download links");
        check(metadata.body().contains("\"issuerId\":\""+repository.credential(rootCredential).orElseThrow().issuerRef().issuerId().value()+"\""),"artifact metadata lost exact issuer generation");
        realm.grant(ServerTestSupport.grant("outsider.read-content","outsider",Permission.Effect.ALLOW,Permission.Action.CERTIFICATE_READ_CONTENT,Permission.ResourceType.CERTIFICATE,scope,Permission.Relationship.ANY,Permission.DataView.CONTENT_FULL),"system");
        check(binaryGet(outsider,content).statusCode()==404,"read-content alone permitted download");
        realm.grant(ServerTestSupport.grant("outsider.download-metadata","outsider",Permission.Effect.ALLOW,Permission.Action.CERTIFICATE_DOWNLOAD,Permission.ResourceType.CERTIFICATE,scope,Permission.Relationship.ANY,Permission.DataView.METADATA_REDACTED),"system");
        check(binaryGet(outsider,content).statusCode()==404,"metadata view permitted content download");
        realm.grant(ServerTestSupport.grant("outsider.download-wrong-scope","outsider",Permission.Effect.ALLOW,Permission.Action.CERTIFICATE_DOWNLOAD,Permission.ResourceType.CERTIFICATE,
                new Permission.Scope(realm.configuration().realmId(),Optional.of(new zeroecho.pki.api.PkiId("unrelated-authority")),Optional.empty(),Optional.empty()),Permission.Relationship.ANY,Permission.DataView.CONTENT_FULL),"system");
        check(binaryGet(outsider,content).statusCode()==404,"wrong authority permitted content download");
        for(String bad:List.of("x509%252Fbad","x509%2Fbad","%2E%2E","x509%2558bad"))check(binaryGet(admin,origin+"/admin/v1/certificate-artifacts/"+bad+"/content?representation=original").statusCode()>=400,"unsafe path accepted");
        var keyGenerator=KeyPairGenerator.getInstance("RSA");keyGenerator.initialize(2048);var leafKey=keyGenerator.generateKeyPair();
        var csrBuilder=new org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder(new org.bouncycastle.asn1.x500.X500Name("CN=private.example.test"),leafKey.getPublic());
        var extensions=new org.bouncycastle.asn1.x509.ExtensionsGenerator();
        extensions.addExtension(org.bouncycastle.asn1.x509.Extension.subjectAlternativeName,false,new org.bouncycastle.asn1.x509.GeneralNames(new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x509.GeneralName.dNSName,"private.example.test")));
        csrBuilder.addAttribute(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,extensions.generate());
        byte[] csr=csrBuilder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(leafKey.getPrivate())).getEncoded();
        var imported=(zeroecho.pki.application.PkiOperationOutcome.Completed)realm.session().operations().execute(new zeroecho.pki.application.PkiOperation.ImportRequest(new zeroecho.pki.api.FormatId("x509"),new zeroecho.pki.api.EncodedObject(zeroecho.pki.api.Encoding.DER,csr)),zeroecho.core.io.CancellationSignal.NONE);
        String requestId=((zeroecho.pki.application.PkiOperationValue.Text)imported.result().fields().get("requestId")).value();
        String leaf="{\"version\":1,\"requestId\":\"private-leaf\",\"operation\":\"credential.issue\",\"authorityId\":\""+ca.caId().value()+"\",\"arguments\":{\"issuerCaId\":\""+ca.caId().value()+"\",\"requestId\":\""+requestId+"\",\"profileId\":\"server-tls\"}}";
        check(post(admin,requests,leaf,"application/json").statusCode()==202,"leaf submission failed");
        var completed=awaitRequest(server,"private-leaf");check(completed.approvalId().isEmpty(),"NONE profile created approval");
        var leafCredential=new zeroecho.pki.api.PkiId(((zeroecho.pki.application.PkiOperationValue.Text)completed.result().orElseThrow().fields().get("credentialId")).value());
        makePrivate(realm,leafCredential,DisclosureService.ObjectType.LEAF_CERTIFICATE);
        certificateBytes(server,admin,leafCredential);
        String inventory="{\"version\":1,\"authorityId\":\""+ca.caId().value()+"\",\"arguments\":{\"limit\":100}}";
        var page=post(admin,origin+"/admin/v1/operations/credential.list",inventory,"application/json");
        check(page.statusCode()==200&&page.body().contains(leafCredential.value())&&page.body().contains(rootCredential.value()),"mandatory inventory lost stored certificates without H2");
        for (String type : List.of("CRL", "DELTA_CRL")) {
            String jobId = "download-" + type.toLowerCase(java.util.Locale.ROOT);
            String job = "{\"version\":1,\"requestId\":\""+jobId+"\",\"operation\":\"status.generate\",\"authorityId\":\""+ca.caId().value()+"\",\"arguments\":{\"issuerCaId\":\""+ca.caId().value()+"\",\"type\":\""+type+"\",\"formatId\":\"x509\"}}";
            var submitted = post(admin, requests, job, "application/json");
            check(submitted.statusCode() == 202, "status submission failed: " + submitted.body());
            var finished = awaitRequest(server, jobId);
            var statusId = ((zeroecho.pki.application.PkiOperationValue.Text) finished.result().orElseThrow().fields().get("statusObjectId")).value();
            String endpoint = origin + "/admin/v1/status-artifacts/" + encoded(statusId);
            var statusMetadata = get(admin, endpoint);
            check(statusMetadata.statusCode() == 200 && statusMetadata.body().contains("\"id\":\"pem\""), "status representations missing: " + statusMetadata.body());
            byte[] stored;
            try (var lease = repository.openStatusObject(new zeroecho.pki.api.PkiId(statusId)); var in = lease.openStream()) { stored = in.readAllBytes(); }
            for (String representation : List.of("original", "pem")) {
                var download = binaryGet(admin, endpoint + "/content?representation=" + representation);
                check(download.statusCode() == 200, "status download failed: " + download.statusCode());
                var parsed = (java.security.cert.X509CRL) java.security.cert.CertificateFactory.getInstance("X.509").generateCRL(new java.io.ByteArrayInputStream(download.body()));
                check(java.util.Arrays.equals(stored, parsed.getEncoded()), "status representation altered signed CRL");
                check(download.headers().firstValue("Content-Disposition").orElse("").contains("attachment"), "missing status attachment");
                check(download.headers().firstValue("Content-Digest").isPresent(), "missing status digest");
            }
            realm.grant(ServerTestSupport.grant("outsider.status-meta."+type,"outsider",Permission.Effect.ALLOW,Permission.Action.CRL_DOWNLOAD,Permission.ResourceType.STATUS_OBJECT,scope,Permission.Relationship.ANY,Permission.DataView.METADATA_REDACTED),"system");
            check(get(outsider,endpoint).body().contains("\"representations\":[]"), "status metadata exposed links");
            realm.grant(ServerTestSupport.grant("outsider.status-wrong."+type,"outsider",Permission.Effect.ALLOW,Permission.Action.CRL_DOWNLOAD,Permission.ResourceType.STATUS_OBJECT,
                    new Permission.Scope(realm.configuration().realmId(),Optional.of(new zeroecho.pki.api.PkiId("wrong-authority")),Optional.empty(),Optional.empty()),Permission.Relationship.ANY,Permission.DataView.CONTENT_FULL),"system");
            check(binaryGet(outsider,endpoint+"/content?representation=original").statusCode()==404,"metadata-only or wrong authority downloaded status bytes");
        }
        System.out.println("PASS private CA+leaf native TLS original/PEM equality, full-content permission negatives, strict IDs, mandatory no-H2 inventory");
    }
    private static AdministrativeRequest awaitRequest(PkiHttpsServer server,String id)throws Exception {
        long until=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30);AdministrativeRequest value;
        do {Thread.sleep(20);value=server.realm().administrativeRequests().inspect(id,"bootstrap-admin");if(value.terminal())break;}while(System.nanoTime()<until);
        check(value.state()==AdministrativeRequest.State.SUCCEEDED,"certificate issuance failed: "+value.state()+value.failureCode());return value;
    }
    private static void makePrivate(ServerRealmContext realm,zeroecho.pki.api.PkiId id,DisclosureService.ObjectType type)throws Exception {
        if(AdministrativeWorkflowFixture.control(realm).findDisclosure(id).isPresent())realm.disclosure().change(id,DisclosureService.Policy.RESTRICTED,true,true,"bootstrap-admin");
        else realm.disclosure().register(id,type,DisclosureService.Policy.RESTRICTED,Optional.of("bootstrap-admin"),"a".repeat(64),"bootstrap-admin");
    }
    private static void certificateBytes(PkiHttpsServer server,HttpClient client,zeroecho.pki.api.PkiId id)throws Exception {
        String origin="https://localhost:"+server.address().getPort();
        var metadata=get(client,origin+"/admin/v1/certificate-artifacts/"+encoded(id.value()));
        check(metadata.statusCode()==200,"certificate metadata unavailable: "+metadata.body());
        // The input codec deliberately excludes null; parse the result projection without the envelope's failure:null.
        String projection=metadata.body().substring(metadata.body().indexOf("\"result\":")+9,metadata.body().lastIndexOf(",\"failure\":"));
        var result=(zeroecho.pki.application.PkiOperationValue.ObjectValue)zeroecho.pki.server.http.StrictJson.parse(projection.getBytes(java.nio.charset.StandardCharsets.UTF_8),65536);
        var value=(zeroecho.pki.application.PkiOperationValue.ObjectValue)result.fields().get("value");
        var representations=(zeroecho.pki.application.PkiOperationValue.ListValue)value.fields().get("representations");
        check(representations.values().size()==2,"X509 format did not advertise original and PEM");byte[] original;
        try(var lease=server.realm().session().repository().openCredential(id);var stream=lease.openStream()){original=stream.readAllBytes();}
        for(var row:representations.values()) {
            var representation=(zeroecho.pki.application.PkiOperationValue.ObjectValue)row;
            String href=((zeroecho.pki.application.PkiOperationValue.Text)representation.fields().get("href")).value();
            var response=binaryGet(client,origin+href);check(response.statusCode()==200,"certificate download failed");
            var certificate=java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(response.body()));
            check(java.util.Arrays.equals(original,certificate.getEncoded()),"downloaded certificate bytes changed");
            String name=((zeroecho.pki.application.PkiOperationValue.Text)representation.fields().get("fileName")).value();
            check(response.headers().firstValue("Content-Disposition").orElseThrow().equals("attachment; filename=\""+name+"\""),"unsafe attachment filename");
            check(response.headers().firstValue("Cache-Control").orElseThrow().equals("no-store")&&response.headers().firstValue("X-Content-Type-Options").orElseThrow().equals("nosniff"),"missing private-content headers");
            if(((zeroecho.pki.application.PkiOperationValue.Text)representation.fields().get("id")).value().equals("original"))check(java.util.Arrays.equals(original,response.body()),"native certificate bytes were transcoded");
        }
    }
    private static String encoded(String id){return java.net.URLEncoder.encode(id,java.nio.charset.StandardCharsets.UTF_8);}
    private static HttpResponse<byte[]> binaryGet(HttpClient client,String url)throws Exception{return client.send(HttpRequest.newBuilder(URI.create(url)).GET().build(),HttpResponse.BodyHandlers.ofByteArray());}

    private static PkiServerConfiguration.ClientCertificateMapping mapping(String id, String principal,
            java.security.cert.X509Certificate certificate) throws Exception {
        return new PkiServerConfiguration.ClientCertificateMapping(id, principal,
                Optional.of(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))),
                Optional.empty(), Optional.empty());
    }
    private static String body(String id, String subject) {
        return "{\"version\":1,\"requestId\":\"" + id + "\",\"operation\":\"ca.create\",\"arguments\":{"
                + "\"formatId\":\"x509\",\"subjectRef\":\"" + subject
                + "\",\"profileId\":\"root-ca\",\"keyRef\":\"fixture:root.prv\"}}";
    }
    private static HttpResponse<String> get(HttpClient client, String url) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString());
    }
    private static HttpResponse<String> post(HttpClient client, String url, String document, String type) throws Exception {
        return client.send(HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(10)).header("Content-Type", type)
                .POST(HttpRequest.BodyPublishers.ofString(document)).build(), HttpResponse.BodyHandlers.ofString());
    }
    private static void check(boolean condition, String failure) { if (!condition) throw new AssertionError(failure); }
    /**
     * Runs the native HTTP workflow fixture directly with one isolated output root.
     *
     * @param args command-line arguments consumed by the direct fixture launcher
     * @throws Exception if fixture setup, protocol assertions or cleanup fails
     */
    public static void main(String[] args) throws Exception { exercise(Files.createTempDirectory("zeroecho-admin-http-")); }
}
