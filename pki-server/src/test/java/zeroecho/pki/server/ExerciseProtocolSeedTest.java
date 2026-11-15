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

import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.*;
import zeroecho.pki.api.*;
import zeroecho.pki.api.profile.*;
import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.audit.*;
import zeroecho.pki.application.*;
import zeroecho.pki.server.http.*;
import static org.junit.jupiter.api.Assertions.*;

/** Real protected custody, runtime validation and protocol wire prerequisites in fresh state. */
@org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named="ZEROECHO_PROTOCOL_INTEGRATION",matches="true")
class ExerciseProtocolSeedTest {
    @Test void ownedSeedLoadsAllProtocolServicesAndRealAcmeEstWire(@TempDir Path root)throws Exception {
        Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwx------"));
        Path repository=Path.of("").toAbsolutePath();if(!Files.isDirectory(repository.resolve("deploy")))repository=repository.getParent();
        String nonce="a".repeat(32),runId="b".repeat(32),password=ExercisePkiIntegrationTest.randomPassword(),tlsPassword=ExercisePkiIntegrationTest.randomPassword();
        String setup="""
                import json,sys
                from pathlib import Path
                sys.path.insert(0,sys.argv[1])
                import exercise_fixture,exercise_environment,rootless_pki
                root=Path(sys.argv[2]); values=json.load(sys.stdin)
                for part in ['config','profiles','provisioning','logins','tls/server','tls/health','tls/edge','tls/upstream','tls/admin-trust','store-container','keyring','audit']:
                    (root/part).mkdir(parents=True,exist_ok=True,mode=0o700)
                rootless_pki._json(root/'.exercise-owner.json',{'nonce':values['nonce']})
                fingerprints=exercise_fixture._tls(root,values['tls'],values['login'])
                rootless_pki._configuration(root,{'realm':'zeroecho-exercise-'+values['nonce'],'admin':'exercise-admin','approver':'exercise-approver','key_password':values['login']},fingerprints)
                config=json.loads((root/'config/server.json').read_text())
                exercise_environment.prepare(root,config)
                for name in ['listener','acmeListener','estListener','scepListener','cmpListener']:
                    config[name]['port']=0
                    config[name]['address']='127.0.0.1'
                    config[name]['tlsProvider']={'id':'test-tls','properties':{}}
                raw=json.dumps(config).replace('/deployment/',str(root)+'/')
                exercise_environment._atomic_json(root/'config/server.json',json.loads(raw))
                """;
        byte[] secrets=StrictJson.encode(object(Map.of("nonce",text(nonce),"tls",text(tlsPassword),"login",text(password))));
        ExercisePkiIntegrationTest.run(new ProcessBuilder("python3","-c",setup,repository.resolve("deploy").toString(),root.toString()),secrets,root.resolve("setup.log"));
        Arrays.fill(secrets,(byte)0);
        Path configPath=root.resolve("config/server.json");byte[] original=Files.readAllBytes(configPath);
        var document=(PkiOperationValue.ObjectValue)StrictJson.parse(original,1048576);var realm=(PkiOperationValue.ObjectValue)document.fields().get("realm");var session=(PkiOperationValue.ObjectValue)realm.fields().get("pkiSession");
        var unsigned=new LinkedHashMap<>(session.fields());unsigned.remove("signing");
        var unsignedConfig=PkiServerConfigurationCodec.decode(StrictJson.encode(with(document,"realm",with(realm,"pkiSession",object(unsigned)))));
        PkiAdminBootstrap.bootstrap(unsignedConfig,"exercise-admin","exercise-approver","trusted-proxy");
        Path keyring=root.resolve("keyring/ca-keyring.zek");
        try(var unlock=new KeyringPassword(password.toCharArray());var ring=KeyringStore.create(keyring,unlock)) {
            var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);
            for(String alias:List.of("root","intermediate","rotation")){var pair=generator.generateKeyPair();ring.putPrivate(alias+".prv","RSA",pair.getPrivate());ring.putPublic(alias+".pub","RSA",pair.getPublic());}
        }
        var config=PkiServerConfigurationCodec.decode(original);var dependencies=PkiSessionRuntimeDependencies.withKeyringUnlockProvider(()->new KeyringPassword(password.toCharArray()));
        String authorityId,credentialId;
        try(var context=ServerRealmContext.open(config.realm(),dependencies)) {
            for(var profile:BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())){context.session().profiles().importBuiltIn(profile);context.session().profiles().activateProfile(profile.definition().profileId(),profile.definition().profileVersion());}
            var signing=context.session().semanticSigning().orElseThrow();
            var prepared=signing.prepareRootCreation(new AccessContext(new Principal("SYSTEM","fixture"),new Purpose("ca.create"),Optional.empty(),Optional.empty()),new CaCreateCommand(new FormatId("x509"),new SubjectRef("CN=ZeroEcho DEMO "+runId),"root-ca",new KeyRef("zeroecho-lib:root.prv"),new zeroecho.pki.impl.core.attr.SimpleAttributeSet(List.of())),CancellationSignal.NONE);
            var accepted=signing.accept(prepared);long until=System.nanoTime()+java.util.concurrent.TimeUnit.SECONDS.toNanos(30);zeroecho.pki.api.signing.SemanticSigningOperation state;
            do{Thread.sleep(20);state=signing.find(accepted.receipt().operationId()).orElseThrow();}while(state.completedCredentialId().isEmpty()&&System.nanoTime()<until);
            credentialId=state.completedCredentialId().orElseThrow().value();var credential=context.session().repository().credential(new PkiId(credentialId)).orElseThrow();authorityId=credential.issuerRef().caId().value();
        }
        var proof=object(Map.of("nonce",text(nonce),"runId",text(runId),"authorityId",text(authorityId),"credentialId",text(credentialId),"backendStopped",new PkiOperationValue.BooleanValue(true),"serverId",text("c".repeat(64)),"ticket",text("d".repeat(32))));
        Path marker=root.resolve(".exercise-protocol-authorization.json");Files.write(marker,StrictJson.encode(proof));Files.setPosixFilePermissions(marker,PosixFilePermissions.fromString("rw-------"));
        assertThrows(IllegalStateException.class,()->ExerciseProtocolSeed.seed(root,nonce,runId,"foreign-authority",credentialId,password.toCharArray()));
        assertFalse(Files.exists(root.resolve("keyring/protocol-custody")));
        String clientPassword="Independent-client-only-password-2026";
        ExerciseProtocolSeed.seed(root,nonce,runId,authorityId,credentialId,password.toCharArray(),clientPassword.toCharArray());
        try(var clientUnlock=new KeyringPassword(clientPassword.toCharArray());
                var clientRing=KeyringStore.open(root.resolve("protocol-client/client.zek"),clientUnlock)) {
            assertTrue(clientRing.getPrivate("client").getEncoded().length>0);
        }
        assertThrows(Exception.class,()->{
            try(var wrongUnlock=new KeyringPassword(password.toCharArray());
                    var ignored=KeyringStore.open(root.resolve("protocol-client/client.zek"),wrongUnlock)) {
                ignored.getPrivate("client");
            }
        });
        assertFalse(Files.exists(marker));
        var runtime=zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration.read(root.resolve("config/enrollment-runtime.json"));
        assertEquals(3,runtime.credentialSets().size());assertEquals(3,runtime.activeCredentials().size());
        assertThrows(Exception.class,()->ExerciseProtocolSeed.seed(root,nonce,runId,authorityId,credentialId,password.toCharArray()));
        java.security.cert.X509Certificate client;
        try(var input=Files.newInputStream(root.resolve("provisioning/administrator.crt"))){client=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);}
        TestTlsProvider.install(ExercisePkiIntegrationTest.tlsContext(root,tlsPassword));
        var mapping=new PkiServerConfiguration.ClientCertificateMapping("admin","exercise-admin",Optional.of(java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(client.getEncoded()))),Optional.empty(),Optional.empty());
        var authentication=new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,List.of(mapping),List.of(),List.of(),Set.of(),Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty(),0,0);
        var wireConfig=new PkiServerConfiguration(config.version(),config.serverName(),config.realm(),config.listener(),authentication,config.execution(),config.runtime(),config.publicListener(),config.acmeListener(),config.estListener(),config.scepListener(),config.cmpListener(),config.auditProjection());
        try(var server=PkiHttpsServer.start(wireConfig,dependencies,Clock.systemUTC(),new java.security.SecureRandom(),getClass().getClassLoader(),Optional.empty(),Optional.of(runtime))) {
            String runner="""
                    import json,sys
                    from pathlib import Path
                    from types import SimpleNamespace
                    sys.path.insert(0,sys.argv[1])
                    from exercise_pki import Api,Exercise
                    import exercise_protocols,shutil
                    root=Path(sys.argv[2]); authority=sys.argv[5]; run=sys.argv[6]
                    api=Api(sys.argv[3],root/'logins/web-ca.pem',root/'provisioning/administrator.crt',root/'provisioning/administrator.key')
                    exercise=Exercise(api,root/'wire-output'); exercise.state['runId']=run; exercise.save(); exercise.discover()
                    policy='exercise-'+run+'-protocol-policy'; endpoint='exercise-'+run+'-endpoint'; alias='exercise-'+run+'-directory'
                    for protocol in ['est','scep','cmp']:
                        args={'label':endpoint,'authorityId':authority,'profileId':'server-tls','enrollmentProfileId':policy}
                        if protocol=='scep':args['challengePasswordHash']='a'*64
                        if protocol=='cmp':args['protectionPolicy']='SIGNATURE_BASED'
                        exercise.job('endpoint-'+protocol,protocol+'.endpoint.register',args,authority)
                    profile=exercise.operation('profile.inspect',{'profileId':'server-tls','profileVersion':1},authority)
                    exercise.job('directory','acme.directory.register',{'alias':alias,'authorityId':authority,'profileId':'server-tls','enrollmentProfileId':policy,'dnsNamespaces':['example.invalid'],'maximumValidityMillis':3600000,'publicKeyAlgorithms':profile['publicKeyAlgorithms'],'x509BindingPolicies':profile['x509BindingPolicies'],'challengeTypes':['DNS_01'],'challengeProviderIds':[exercise_protocols.DNS_PROVIDER],'eabRequired':False},authority)
                    directories=exercise.operation('acme.directory.list',{'offset':0,'limit':10})
                    directory=directories['items'][0]
                    exercise.job('activate','acme.directory.activate',{'directoryId':directory['directoryId']})
                    client=root/'client-export';(client/'public').mkdir(parents=True)
                    for source,target in [('keyring/protocol-custody/authority.der','public/authority.der'),('logins/web-ca.pem','trust.pem'),('provisioning/approver.crt','requester.crt'),('provisioning/approver.key','requester.key')]:shutil.copyfile(root/source,client/target)
                    fixture=SimpleNamespace(directory=client,protocol_urls={'acme':sys.argv[4],'est':sys.argv[7],'scep':sys.argv[8]},trust_file=client/'trust.pem',requester_certificate=client/'requester.crt',requester_key=client/'requester.key',acme_origin='https://localhost:8445')
                    values={'directoryAlias':alias,'endpointLabel':endpoint}
                    account=exercise_protocols._wire_account(exercise,fixture,values)
                    exercise.operation('acme.account.inspect',{'accountId':account})
                    exercise_protocols._wire_scep(exercise,fixture,values)
                    pending=exercise_protocols._wire_pending(exercise,fixture,values)
                    assert len(pending)==2
                    print('ACTUAL_ACME_ACCOUNT_AND_TWO_EST_PENDING_PASS')
                    """;
            ExercisePkiIntegrationTest.run(new ProcessBuilder("python3","-c",runner,repository.resolve("deploy").toString(),root.toString(),"https://localhost:"+server.address().getPort(),"https://localhost:"+server.acmeAddress().orElseThrow().getPort(),authorityId,runId,"https://localhost:"+server.estAddress().orElseThrow().getPort(),"https://localhost:"+server.scepAddress().orElseThrow().getPort()),new byte[0],root.resolve("wire.log"));
            ExerciseProtocolSeed.cmpWire(root,nonce,runId,java.net.URI.create("https://localhost:"+server.cmpAddress().orElseThrow().getPort()),"exercise-"+runId+"-endpoint",clientPassword.toCharArray());
        }
    }
    private static PkiOperationValue.ObjectValue object(Map<String,PkiOperationValue> fields){return new PkiOperationValue.ObjectValue(fields);}
    private static PkiOperationValue.Text text(String value){return new PkiOperationValue.Text(value);}
    private static PkiOperationValue.ObjectValue with(PkiOperationValue.ObjectValue value,String key,PkiOperationValue next){var fields=new LinkedHashMap<>(value.fields());fields.put(key,next);return object(fields);}
}
