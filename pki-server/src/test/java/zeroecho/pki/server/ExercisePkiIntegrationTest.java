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

import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.json.JsonFactory;
import zeroecho.pki.server.http.TestTlsProvider;

/**
 * Opt-in real HTTPS qualification of the operator script against fresh PKI state.
 * Requires Python and OpenSSL; passwords enter subprocesses through stdin only.
 * Enable with ZEROECHO_EXERCISE_INTEGRATION=true and the ordinary server test task.
 */
@EnabledIfEnvironmentVariable(named="ZEROECHO_EXERCISE_INTEGRATION", matches="true")
class ExercisePkiIntegrationTest {
    @Test
    void operatorScriptCreatesConfirmsRevokesAndCryptographicallyChecksRealArtifacts(@TempDir Path directory) throws Exception {
        Path repository=Path.of("").toAbsolutePath();
        if (!Files.isDirectory(repository.resolve("deploy"))) repository=repository.getParent();
        Path transport=directory.resolve("tls");
        Files.createDirectories(transport);
        String tlsPassword=randomPassword();
        String loginPassword=randomPassword();
        String tlsRunner="""
                import json,sys
                from pathlib import Path
                sys.path.insert(0, sys.argv[1])
                from exercise_fixture import _tls
                root=Path(sys.argv[2])
                for name in ['provisioning','logins','tls/server','tls/health','tls/edge','tls/upstream','tls/admin-trust']:
                    (root/name).mkdir(parents=True,exist_ok=True,mode=0o700)
                passwords=json.load(sys.stdin)
                _tls(root,passwords['tls'],passwords['login'])
                """;
        String passwords="{\"tls\":\""+tlsPassword+"\",\"login\":\""+loginPassword+"\"}";
        run(new ProcessBuilder("python3","-c",tlsRunner,repository.resolve("deploy").toString(),transport.toString()),
                passwords.getBytes(StandardCharsets.UTF_8),directory.resolve("tls-stage.log"));
        X509Certificate client;
        try(var in=Files.newInputStream(transport.resolve("provisioning/administrator.crt"))) {
            client=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        SSLContext ssl=tlsContext(transport,tlsPassword);
        var listener=HttpServerTestSupport.configuration(directory.resolve("transport-configuration"),client).listener();
        TestTlsProvider.install(ssl);
        var unsigned=AdministrativeWorkflowFixture.configuration(directory.resolve("domain"),false);
        PkiAdminBootstrap.bootstrap(unsigned,"bootstrap-admin","bootstrap-approver","trusted-proxy");
        var domain=AdministrativeWorkflowFixture.configuration(directory.resolve("domain"),true);
        var mapping=new PkiServerConfiguration.ClientCertificateMapping("admin","bootstrap-admin",
                Optional.of(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(client.getEncoded()))),Optional.empty(),Optional.empty());
        var authentication=new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(mapping),List.of(),List.of(),Set.of(),Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty(),0,0);
        var configuration=new PkiServerConfiguration(domain.version(),domain.serverName(),domain.realm(),listener,authentication,domain.execution(),domain.runtime());
        Path keyPath=directory.resolve("domain/keyring/signing.zek");
        Files.createDirectories(keyPath.getParent(),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try(var password=new KeyringPassword(AdministrativeWorkflowFixture.PASSWORD.toCharArray());var keys=KeyringStore.create(keyPath,password)) {
            var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);
            var pair=generator.generateKeyPair();
            keys.putPrivate("root.prv","RSA",pair.getPrivate());keys.putPublic("root.pub","RSA",pair.getPublic());
        }
        var dependencies=PkiSessionRuntimeDependencies.withKeyringUnlockProvider(()->new KeyringPassword(AdministrativeWorkflowFixture.PASSWORD.toCharArray()));
        try(var realm=ServerRealmContext.open(configuration.realm(),dependencies)) {
            for(var profile:BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())) {
                if(Set.of("root-ca","vpn-client").contains(profile.definition().profileId())) {
                    realm.session().profiles().importBuiltIn(profile);
                    realm.session().profiles().activateProfile(profile.definition().profileId(),profile.definition().profileVersion());
                }
            }
        }
        try(var server=PkiHttpsServer.start(configuration,dependencies,Clock.systemUTC(),new SecureRandom(),getClass().getClassLoader())) {
            String origin="https://localhost:"+server.address().getPort();
            String runner="""
                    import sys
                    sys.path.insert(0,sys.argv[1])
                    import exercise_pki
                    exercise_pki.getpass.getpass=lambda prompt:sys.stdin.readline().rstrip('\\n')
                    raise SystemExit(exercise_pki.main(['--url',sys.argv[2],'--admin-p12',sys.argv[3],'--trust',sys.argv[4],'--output',sys.argv[5],'--ca-key-ref','fixture:root.prv','--principal-id','bootstrap-admin']))
                    """;
            Path output=directory.resolve("artifacts");
            run(new ProcessBuilder("python3","-c",runner,repository.resolve("deploy").toString(),origin,
                    transport.resolve("logins/administrator.p12").toString(),transport.resolve("logins/web-ca.pem").toString(),output.toString()),
                    (loginPassword+"\n").getBytes(StandardCharsets.UTF_8),directory.resolve("script.log"));
            var report=diagnosticObject(output.resolve("report.json"));
            assertEquals(Boolean.TRUE,report.get("demoVerified"));
            assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(output.resolve("client.key")));
            for(String name:List.of("ca.der","ca.pem","client.der","client.pem","full.der","full.pem","delta.der","delta.pem","full-after.der","full-after.pem")) assertTrue(Files.size(output.resolve(name))>0,name);
            var checkpoint=diagnosticObject(output.resolve("checkpoint.json"));
            var jobs=assertInstanceOf(Map.class,checkpoint.get("jobs"));
            assertFalse(jobs.isEmpty(),"The external client must retain real completed requests");
            for(var value:jobs.values()) {
                var retained=assertInstanceOf(Map.class,value);
                var intent=assertInstanceOf(Map.class,retained.get("intent"));
                String id=assertInstanceOf(String.class,intent.get("requestId"));
                assertEquals(AdministrativeRequest.State.SUCCEEDED,server.realm().administrativeRequests().inspect(id,"bootstrap-admin").state());
            }
        }
    }

    private static Map<?,?> diagnosticObject(Path path) throws Exception {
        assertTrue(Files.size(path)<=8*1024*1024,"Client diagnostic document exceeds test bound");
        try(var parser=JsonFactory.builder().build().createParser(ObjectReadContext.empty(),Files.readAllBytes(path))) {
            assertNotNull(parser.nextToken(),"Client diagnostic document is empty");
            var result=assertInstanceOf(Map.class,diagnosticValue(parser));
            assertNull(parser.nextToken(),"Client diagnostic document has trailing content");
            return result;
        }
    }

    // Client diagnostics allow JSON null, unlike the deliberately restricted server wire algebra.
    private static Object diagnosticValue(JsonParser parser) throws java.io.IOException {
        return switch(parser.currentToken()) {
            case START_OBJECT -> {
                Map<String,Object> result=new LinkedHashMap<>();
                while(parser.nextToken()!=JsonToken.END_OBJECT) {
                    assertEquals(JsonToken.PROPERTY_NAME,parser.currentToken());
                    String name=parser.currentName();
                    assertFalse(result.containsKey(name),"Duplicate diagnostic field");
                    assertNotNull(parser.nextToken());
                    result.put(name,diagnosticValue(parser));
                }
                yield result;
            }
            case START_ARRAY -> {
                List<Object> result=new ArrayList<>();
                while(parser.nextToken()!=JsonToken.END_ARRAY) {
                    assertNotNull(parser.currentToken());
                    result.add(diagnosticValue(parser));
                }
                yield result;
            }
            case VALUE_STRING -> parser.getString();
            case VALUE_TRUE -> true;
            case VALUE_FALSE -> false;
            case VALUE_NULL -> null;
            case VALUE_NUMBER_INT -> parser.getBigIntegerValue();
            case VALUE_NUMBER_FLOAT -> parser.getDecimalValue();
            default -> throw new java.io.IOException("Unexpected client diagnostic JSON token");
        };
    }

    static String randomPassword() {
        byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static SSLContext tlsContext(Path root,String password) throws Exception {
        KeyStore identity=KeyStore.getInstance("PKCS12");
        try(var in=Files.newInputStream(root.resolve("tls/server/server-identity.p12"))){identity.load(in,password.toCharArray());}
        KeyStore trust=KeyStore.getInstance("PKCS12");
        try(var in=Files.newInputStream(root.resolve("tls/server/trust.p12"))){trust.load(in,password.toCharArray());}
        var keys=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());keys.init(identity,password.toCharArray());
        var trusted=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());trusted.init(trust);
        var context=SSLContext.getInstance("TLS");context.init(keys.getKeyManagers(),trusted.getTrustManagers(),new SecureRandom());return context;
    }

    static void run(ProcessBuilder builder,byte[] input,Path log) throws Exception {
        Process process=builder.redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try(OutputStream in=process.getOutputStream()){in.write(input);}
        if(!process.waitFor(Duration.ofMinutes(3).toMillis(),TimeUnit.MILLISECONDS)) {
            process.destroy();
            if(!process.waitFor(5,TimeUnit.SECONDS))process.destroyForcibly();
            fail("Python qualification timed out");
        }
        assertEquals(0,process.exitValue(),()->"Python qualification failed: "+read(log));
    }

    private static String read(Path path) {
        try{return Files.readString(path);}catch(java.io.IOException failure){return "Diagnostic file unreadable";}
    }
}
