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
 * Opt-in real HTTPS catalog diagnostics against fresh independently owned PKI state.
 * Optional protocol and binary-backup scenarios remain explicitly outside this partial gate.
 * Requires Python and OpenSSL; passwords enter subprocesses through stdin only.
 * Enable with ZEROECHO_EXERCISE_INTEGRATION=true and the ordinary server test task.
 */
@EnabledIfEnvironmentVariable(named="ZEROECHO_EXERCISE_INTEGRATION", matches="true")
class ExerciseCatalogIntegrationTest {
    /**
     * Runs catalog client recipes against HTTPS with real issuance approval and observes their terminal workflow results.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test
    void catalogRecipesObserveRealHttpsTerminalResults(@TempDir Path directory) throws Exception {
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
        var unsigned=withRecipePrerequisites(AdministrativeWorkflowFixture.configuration(directory.resolve("domain"),false));
        assertEquals(1,unsigned.realm().approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_SINGLE).threshold());
        PkiAdminBootstrap.bootstrap(unsigned,"bootstrap-admin","bootstrap-approver","trusted-proxy");
        var domain=withRecipePrerequisites(AdministrativeWorkflowFixture.configuration(directory.resolve("domain"),true));
        var mapping=new PkiServerConfiguration.ClientCertificateMapping("admin","bootstrap-admin",
                Optional.of(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(client.getEncoded()))),Optional.empty(),Optional.empty());
        var authentication=new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(mapping),List.of(),List.of(),Set.of(),Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty(),0,0);
        var realmBase=domain.realm();
        var sessionBase=realmBase.pkiSessionConfiguration();
        var props=new java.util.HashMap<>(sessionBase.store().properties());
        props.put("credentialSearch","h2");
        props.put("credentialSearchCacheKiB","4096");props.put("credentialSearchQueryTimeoutMillis","10000");props.put("credentialSearchMaximumCertificateBytes","1048576");
        Path publicationRoot=directory.resolve("artifacts/publication");Files.createDirectories(publicationRoot);
        var session=new zeroecho.pki.application.PkiSessionConfiguration(sessionBase.version(),
            new zeroecho.pki.spi.ProviderConfig("fs",props),new zeroecho.pki.spi.ProviderConfig("file",java.util.Map.of("root",directory.resolve("domain/audit").toString())),sessionBase.signing(),
            List.of(new zeroecho.pki.spi.ProviderConfig("filesystem",java.util.Map.of("root",publicationRoot.toString(),"targetId","exercise-files"))),sessionBase.bindingProviders());
        var realmConfiguration=new ServerRealmConfiguration(realmBase.realmId(),realmBase.displayName(),realmBase.confirmationProofPolicy(),session,
            realmBase.authorityExposure(),realmBase.authorizationCommitment(),realmBase.approvalCommitment(),realmBase.extendedApprovalCommitment(),
            realmBase.disclosureCommitment(),realmBase.disclosureDefaults(),realmBase.controlLogPath(),realmBase.controlStoreId(),realmBase.approvalPolicies(),realmBase.initialAdministratorPrincipalId());
        var configuration=new PkiServerConfiguration(domain.version(),domain.serverName(),realmConfiguration,listener,authentication,domain.execution(),domain.runtime());
        Path keyPath=directory.resolve("domain/keyring/signing.zek");
        Files.createDirectories(keyPath.getParent(),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try(var password=new KeyringPassword(AdministrativeWorkflowFixture.PASSWORD.toCharArray());var keys=KeyringStore.create(keyPath,password)) {
            var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);
            for(String alias:List.of("root","intermediate","rotation")) {
                var pair=generator.generateKeyPair();
                keys.putPrivate(alias+".prv","RSA",pair.getPrivate());keys.putPublic(alias+".pub","RSA",pair.getPublic());
            }
        }
        var dependencies=PkiSessionRuntimeDependencies.withKeyringUnlockProvider(()->new KeyringPassword(AdministrativeWorkflowFixture.PASSWORD.toCharArray()));
        try(var realm=ServerRealmContext.open(configuration.realm(),dependencies)) {
            for(var profile:BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())) {
                {
                    realm.session().profiles().importBuiltIn(profile);
                    realm.session().profiles().activateProfile(profile.definition().profileId(),profile.definition().profileVersion());
                }
            }
        }
        try(var server=PkiHttpsServer.start(configuration,dependencies,Clock.systemUTC(),new SecureRandom(),getClass().getClassLoader())) {
            String origin="https://localhost:"+server.address().getPort();
            String runner="""
                    import sys,tempfile,json
                    from pathlib import Path
                    from types import SimpleNamespace
                    sys.path.insert(0,sys.argv[1])
                    import exercise_pki,exercise_catalog
                    password=sys.stdin.readline().rstrip('\\n')
                    output=Path(sys.argv[5]); owned=Path(sys.argv[6])
                    with tempfile.TemporaryDirectory() as temporary:
                        cert,key=exercise_pki._identity(Path(temporary),Path(sys.argv[3]),password)
                        exercise=exercise_pki.Exercise(exercise_pki.Api(sys.argv[2],Path(sys.argv[4]),cert,key),output)
                        options=SimpleNamespace(principal_id='bootstrap-admin',ca_key_ref='fixture:root.prv',ca_profile='root-ca',client_profile='vpn-client',maximum_download_bytes=67108864,require_public=False)
                        exercise_pki._live(exercise,options)
                        excluded=lambda op: op!='ocsp.responder.issue-certificate' and (op.startswith(('backup.','acme.','est.','scep.','cmp.','enrollment.request.','ocsp.')) or op in {'publication.retry','publication.reconcile'})
                        exercise.descriptors={op:desc for op,desc in exercise.descriptors.items() if not excluded(op)}
                        def assert_owned(origin,run_id):
                            assert origin==sys.argv[2] and run_id==exercise.state['runId'] and owned.is_dir()
                        context={'assert_disposable':assert_owned,'objects':exercise.state['objects'],'isolatedRoot':str(owned),'adminPrincipalId':'bootstrap-admin',
                                 'rootKeyRef':'fixture:root.prv','intermediateKeyRef':'fixture:intermediate.prv','rotationKeyRef':'fixture:rotation.prv'}
                        result=exercise_catalog.run(exercise,context)
                        print(json.dumps(result,sort_keys=True))
                        trace={name:{'requestId':step['intent']['requestId'],'operation':step['intent']['operation'],
                            'submissionDiagnostic':step.get('submissionDiagnostic'),'decisionAttempted':step.get('decisionAttempted'),
                            'state':step.get('receipt',{}).get('state'),'failureCode':step.get('receipt',{}).get('failureCode')}
                            for name,step in exercise.state['jobs'].items() if step['intent']['operation'] in result['failed']}
                        print('SAFE_DURABLE_TRACE '+json.dumps(trace,sort_keys=True))
                        assert not result['qualified'], 'Partial native diagnostics must never claim global qualification'
                        for operation in ('ca.rollover','issuer.path.select'):
                            retained=next(step for step in exercise.state['jobs'].values() if step['intent']['operation']==operation)
                            assert retained['receipt']['state']=='SUCCEEDED', 'Regression prerequisite: lifecycle mutation did not complete'
                            from urllib.parse import quote
                            for _ in range(2):
                                _,wire=exercise.api.json('GET','/admin/v1/requests/'+quote(retained['intent']['requestId'],safe=''))
                                projected=exercise_pki._result(wire,'administrative.request.inspect')
                                assert isinstance(projected.get('result'),dict), 'Completed lifecycle result must survive head change: '+operation
                                assert 'target' in projected, 'Current authorized viewer must retain exact original target'
                        assert not result['failed'], json.dumps(result['failed'],sort_keys=True)
                    """;
            Path output=directory.resolve("http-receipts");
            run(new ProcessBuilder("python3","-c",runner,repository.resolve("deploy").toString(),origin,
                    transport.resolve("logins/administrator.p12").toString(),transport.resolve("logins/web-ca.pem").toString(),output.toString(),directory.toString()),
                    (loginPassword+"\n").getBytes(StandardCharsets.UTF_8),directory.resolve("catalog-script.log"));
        }
    }

    private static PkiServerConfiguration withRecipePrerequisites(PkiServerConfiguration source) {
        // The generation recipe must use the same immutable FIRST provenance as deployment bootstrap.
        var realm=source.realm();
        // The managed responder profile retains SINGLE approval; this fixture must supply its policy.
        var policies=new java.util.HashMap<>(realm.approvalPolicies());
        policies.put(OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_SINGLE,
                policies.get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK));
        var pinned=new ServerRealmConfiguration(realm.realmId(),realm.displayName(),realm.confirmationProofPolicy(),
                realm.pkiSessionConfiguration(),realm.authorityExposure(),realm.authorizationCommitment(),realm.approvalCommitment(),
                ServerRealmConfiguration.extendedApprovalCommitment(policies),realm.disclosureCommitment(),realm.disclosureDefaults(),realm.controlLogPath(),
                realm.controlStoreId(),policies,Optional.of("bootstrap-admin"));
        return new PkiServerConfiguration(source.version(),source.serverName(),pinned,source.listener(),source.authentication(),
                source.execution(),source.runtime(),source.publicListener(),source.acmeListener(),source.estListener(),source.scepListener(),source.cmpListener(),source.auditProjection());
    }

    /**
     * Creates an independent random unlock password for an isolated qualification fixture.
     *
     * @return unpadded base64url encoding of 32 fresh random bytes
     */
    static String randomPassword() {
        byte[] bytes=new byte[32];new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Loads the fixture server identity and trust store into an independent TLS client context.
     *
     * @param root owned qualification environment root
     * @param password fixture PKCS #12 unlock password
     * @return initialized TLS context with fixture identity and trust anchors
     * @throws Exception if fixture stores cannot be read/unlocked or TLS initialization fails
     */
    static SSLContext tlsContext(Path root,String password) throws Exception {
        KeyStore identity=KeyStore.getInstance("PKCS12");
        try(var in=Files.newInputStream(root.resolve("tls/server/server-identity.p12"))){identity.load(in,password.toCharArray());}
        KeyStore trust=KeyStore.getInstance("PKCS12");
        try(var in=Files.newInputStream(root.resolve("tls/server/trust.p12"))){trust.load(in,password.toCharArray());}
        var keys=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());keys.init(identity,password.toCharArray());
        var trusted=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());trusted.init(trust);
        var context=SSLContext.getInstance("TLS");context.init(keys.getKeyManagers(),trusted.getTrustManagers(),new SecureRandom());return context;
    }

    /**
     * Runs the external qualification client with explicit standard input and bounded process lifetime.
     *
     * @param builder fully configured client process command/environment
     * @param input caller-supplied client input bytes, written before its standard input closes
     * @param log destination for combined process diagnostics
     * @throws Exception if process start, input writing, waiting or diagnostic retention fails
     * @throws AssertionError if the client exceeds its deadline or exits unsuccessfully
     */
    static void run(ProcessBuilder builder,byte[] input,Path log) throws Exception {
        Process process=builder.redirectErrorStream(true).redirectOutput(log.toFile()).start();
        try(OutputStream in=process.getOutputStream()){in.write(input);}
        if(!process.waitFor(Duration.ofMinutes(3).toMillis(),TimeUnit.MILLISECONDS)) {
            process.destroy();
            if(!process.waitFor(5,TimeUnit.SECONDS))process.destroyForcibly();
            fail("Python qualification timed out");
        }
        Path retained=Path.of("build/exercise-catalog-native.log");Files.createDirectories(retained.getParent());Files.copy(log,retained,java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertEquals(0,process.exitValue(),()->"Python qualification failed: "+read(log));
    }

    private static String read(Path path) {
        try{return Files.readString(path);}catch(java.io.IOException failure){return "Diagnostic file unreadable";}
    }
}
