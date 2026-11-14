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
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.StrictJson;
import zeroecho.pki.server.http.TestTlsProvider;

/**
 * Opt-in real HTTPS binary-backup and cold-restore qualification against fresh PKI state.
 * Requires Python and OpenSSL; passwords enter subprocesses through stdin only.
 * Enable with ZEROECHO_EXERCISE_INTEGRATION=true and the ordinary server test task.
 */
@EnabledIfEnvironmentVariable(named="ZEROECHO_EXERCISE_INTEGRATION", matches="true")
class ExerciseBackupIntegrationTest {
    @Test
    void operatorScriptTransfersAndColdRestoresActualBackup(@TempDir Path directory) throws Exception {
        Path repository=Path.of("").toAbsolutePath();
        if (!Files.isDirectory(repository.resolve("deploy"))) repository=repository.getParent();
        Path transport=directory.resolve("tls");
        Files.createDirectories(transport);
        String tlsPassword=ExercisePkiIntegrationTest.randomPassword();
        String loginPassword=ExercisePkiIntegrationTest.randomPassword();
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
        ExercisePkiIntegrationTest.run(new ProcessBuilder("python3","-c",tlsRunner,repository.resolve("deploy").toString(),transport.toString()),
                passwords.getBytes(StandardCharsets.UTF_8),directory.resolve("tls-stage.log"));
        X509Certificate client;
        try(var in=Files.newInputStream(transport.resolve("provisioning/administrator.crt"))) {
            client=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
        SSLContext ssl=ExercisePkiIntegrationTest.tlsContext(transport,tlsPassword);
        var listener=HttpServerTestSupport.configuration(directory.resolve("transport-configuration"),client).listener();
        TestTlsProvider.install(ssl);
        var unsigned=AdministrativeWorkflowFixture.configuration(directory.resolve("domain"),false);
        PkiAdminBootstrap.bootstrap(unsigned,"bootstrap-admin","bootstrap-approver","trusted-proxy");
        var domain=AdministrativeWorkflowFixture.configuration(directory.resolve("domain"),true);
        var mapping=new PkiServerConfiguration.ClientCertificateMapping("admin","bootstrap-admin",
                Optional.of(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(client.getEncoded()))),Optional.empty(),Optional.empty());
        var authentication=new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(mapping),List.of(),List.of(),Set.of(),Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty(),0,0);
        int port;
        try(var reserved=new java.net.ServerSocket(0,1,java.net.InetAddress.getLoopbackAddress())) { port=reserved.getLocalPort(); }
        var fixedListener=new PkiServerConfiguration.Listener(listener.address(),port,listener.tlsProvider(),listener.clientCertificateRequired(),listener.maximumHeaderBytes(),listener.maximumBodyBytes());
        var configuration=new PkiServerConfiguration(domain.version(),domain.serverName(),domain.realm(),fixedListener,authentication,domain.execution(),domain.runtime());
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
        Path spool=directory.resolve("backup-spool");Files.createDirectory(spool,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        String origin="https://localhost:"+port;
        var transfer=new BackupTransferConfiguration(spool,8*1024*1024,16*1024*1024,4,2,18L*1024*1024*1024,Duration.ofHours(1),Duration.ofSeconds(30),java.net.URI.create(origin));
        PkiHttpsServer server=PkiHttpsServer.start(configuration,dependencies,Clock.systemUTC(),new SecureRandom(),getClass().getClassLoader(),Optional.of(transfer));
        Process process=null;
        try {
            String runner="""
                    import sys,time,tempfile
                    from pathlib import Path
                    sys.path.insert(0,sys.argv[1])
                    import exercise_pki as e
                    transport=Path(sys.argv[3]); output=Path(sys.argv[4]); ipc=Path(sys.argv[5])
                    password=sys.stdin.readline().rstrip('\\n')
                    with tempfile.TemporaryDirectory() as temporary:
                        certificate,key=e._identity(Path(temporary),transport/'logins/administrator.p12',password)
                        api=e.Api(sys.argv[2],transport/'logins/web-ca.pem',certificate,key)
                        run=e.Exercise(api,output)
                        run.discover()
                        def owned(origin,run_id):
                            if origin!=api.origin or run_id!=run.state['runId']: raise e.ExerciseFailure('Wrong disposable fixture identity')
                        def restart():
                            (ipc/'restart').write_text(run.state['runId'])
                            deadline=time.monotonic()+60
                            while not (ipc/'ready').exists():
                                if time.monotonic()>deadline: raise e.ExerciseFailure('Native cold restart deadline')
                                time.sleep(.05)
                        context={'assert_disposable':owned,'restart':restart}
                        operations=['backup.export','backup.verify','backup.stream.export','backup.stream.download','backup.stream.reserve','backup.stream.upload','backup.stream.verify','backup.stream.status','backup.stream.restore','backup.stream.acknowledge']
                        for operation in operations:
                            try: e._backup_transfer(run,operation,{},context)
                            except e.ExternalRestartRequired:
                                restart()
                                e._backup_transfer(run,operation,{},context)
                        assert all(run.state['coverage'][op]['state']=='EXECUTED' for op in operations)
                        assert run.state['backupScenario']['receipts']['backup.stream.restore']['state']=='ACTIVATED'
                        run.close()
                    """;
            Path ipc=directory.resolve("ipc");Files.createDirectory(ipc);
            Path log=directory.resolve("backup-script.log");
            process=new ProcessBuilder("python3","-c",runner,repository.resolve("deploy").toString(),origin,transport.toString(),directory.resolve("output").toString(),ipc.toString()).redirectErrorStream(true).redirectOutput(log.toFile()).start();
            try(var input=process.getOutputStream()){input.write((loginPassword+"\n").getBytes(StandardCharsets.UTF_8));}
            long deadline=System.nanoTime()+Duration.ofMinutes(3).toNanos();boolean restarted=false;
            while(process.isAlive()&&System.nanoTime()<deadline) {
                if(!restarted&&Files.exists(ipc.resolve("restart"))) {
                    server.close();
                    server=PkiHttpsServer.start(configuration,dependencies,Clock.systemUTC(),new SecureRandom(),getClass().getClassLoader(),Optional.of(transfer));
                    restarted=true;Files.writeString(ipc.resolve("ready"),"ready");
                }
                Thread.sleep(25);
            }
            assertFalse(process.isAlive(),"Backup qualification deadline");
            assertEquals(0,process.exitValue(),()->{try{return Files.readString(log);}catch(Exception error){return "Cannot read private diagnostic";}});
            assertTrue(restarted,"Actual cold server reopen must occur");
        } finally {
            if(process!=null&&process.isAlive())process.destroyForcibly();
            server.close();
        }
    }
}
