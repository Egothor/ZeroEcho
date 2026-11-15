package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.hybrid.HybridCertificateMode;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkProofs;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileDocumentCodec;
import zeroecho.pki.api.profile.IssuanceApprovalRequirement;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.HttpOperationCodec;
import zeroecho.pki.server.http.StrictJson;
import zeroecho.pki.spi.crypto.ManagedKeyGeneration;
import zeroecho.pkix.Pkix;

/** Real native-domain hierarchy and SDK workflow; certificate transport identities are trusted fixtures, not live mTLS. */
class HybridSdkRealIssuanceTest {
    @Test void realHybridHierarchyAndProofApprovedLeafSurviveRestartWithoutChangingFrozenValidityOrCreationDefault(@TempDir Path root)throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        var original=withIssuancePolicy(ManagedKeyGenerationIntegrationTest.configuration(root));
        PkiAdminBootstrap.bootstrap(ManagedKeyGenerationIntegrationTest.withoutSigning(original),"administrator","approver","trusted-proxy");
        var clock=new TestClock();PkiId rootCredential,intermediateCredential,intermediateAuthority;
        HybridSdkAdmissionService.Challenge challenge;byte[] first,second;
        var client=client();String requestId=HybridSdkProofs.parse(client.csr()).primary().requestId().value();
        PkiOperationValue.ObjectValue leafEnvelope;
        try(var realm=ServerRealmContext.open(original.realm(),dependencies(),clock,new java.security.SecureRandom())) {
            var keys=realm.session().managedKeyGeneration().orElseThrow();
            var rootPrimary=keys.generate("1".repeat(64),ManagedKeyGeneration.Parameters.ECDSA_P384);
            var rootAlternative=keys.generate("2".repeat(64),ManagedKeyGeneration.Parameters.ML_DSA_87);
            var intermediatePrimary=keys.generate("3".repeat(64),ManagedKeyGeneration.Parameters.ECDSA_P384);
            var intermediateAlternative=keys.generate("4".repeat(64),ManagedKeyGeneration.Parameters.ML_DSA_87);
            var classical=keys.generate("5".repeat(64),ManagedKeyGeneration.Parameters.RSA_4096);
            var pqc=keys.generate("6".repeat(64),ManagedKeyGeneration.Parameters.ML_DSA_87);
            install(realm,"root-ca","native-root",new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),rootAlternative.keyRef().value()),IssuanceApprovalRequirement.NONE);
            install(realm,"intermediate-ca","native-intermediate",new HybridCertificateMode.AltSignature(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),intermediateAlternative.keyRef().value()),IssuanceApprovalRequirement.NONE);
            install(realm,"vpn-client","native-leaf",HybridCertificateMode.AltSignature.requested(BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm()),IssuanceApprovalRequirement.SINGLE);
            for(var template:BuiltInCertificateProfileCatalog.load(getClass().getClassLoader())) {
                if(List.of("root-ca","pqc-root-ca").contains(template.definition().profileId())) {
                    realm.session().profiles().importBuiltIn(template);realm.session().profiles().activateProfile(template.definition().profileId(),template.definition().profileVersion());
                }
            }
            var rootRequest=submit(realm,"root","ca.create",arguments("formatId","x509","subjectRef","CN=Native Hybrid Root","profileId","native-root","keyRef",rootPrimary.keyRef().value(),"signatureAlgorithmId",BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm()));
            approve(realm,rootRequest);rootCredential=credential(process(realm.administrativeRequests(),"root"));
            var rootAuthority=authority(realm,rootCredential);
            var intermediate=submit(realm,"intermediate","ca.intermediate.create",arguments("formatId","x509","issuerCaId",rootAuthority.value(),"subjectRef","CN=Native Hybrid Intermediate","profileId","native-intermediate","keyRef",intermediatePrimary.keyRef().value(),"signatureAlgorithmId",BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm()));
            approve(realm,intermediate);intermediateCredential=credential(process(realm.administrativeRequests(),"intermediate"));intermediateAuthority=authority(realm,intermediateCredential);
            var defaultArguments=arguments("formatId","x509","subjectRef","CN=Classical Default","profileId","root-ca","keyRef",classical.keyRef().value());
            var explicitArguments=new TreeMap<>(defaultArguments.fields());explicitArguments.put("signatureAlgorithmId",new PkiOperationValue.Text(original.realm().pkiSessionConfiguration().signing().orElseThrow().signatureAlgorithm()));
            var implicitApproval=assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,realm.gateway().execute(request(realm,"ca.create",envelope(defaultArguments)),zeroecho.core.io.CancellationSignal.NONE));
            var explicitApproval=assertInstanceOf(ServerOperationGateway.Outcome.ApprovalRequired.class,realm.gateway().execute(request(realm,"ca.create",envelope(new PkiOperationValue.ObjectValue(explicitArguments))),zeroecho.core.io.CancellationSignal.NONE));
            assertEquals(implicitApproval.operationCommitment(),explicitApproval.operationCommitment());
            var pendingDefault=submit(realm,"default-frozen","ca.create",defaultArguments);
            var frozenArgs=(PkiOperationValue.ObjectValue)pendingDefault.envelope().fields().get("arguments");
            assertEquals(original.realm().pkiSessionConfiguration().signing().orElseThrow().signatureAlgorithm(),((PkiOperationValue.Text)frozenArgs.fields().get("signatureAlgorithmId")).value());
            var pqcRequest=submit(realm,"pqc","ca.create",arguments("formatId","x509","subjectRef","CN=PQC Root","profileId","pqc-root-ca","keyRef",pqc.keyRef().value(),"signatureAlgorithmId",BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm()));
            approve(realm,pqcRequest);var pqcCertificate=certificate(realm,credential(process(realm.administrativeRequests(),"pqc")));
            assertEquals("2.16.840.1.101.3.4.3.19",pqcCertificate.getSigAlgOID());pqcCertificate.verify(pqcCertificate.getPublicKey());
            leafEnvelope=envelope(arguments("issuerCaId",intermediateAuthority.value(),"requestId",requestId,"profileId","native-leaf"));
            assertNotEquals(rootAuthority,intermediateAuthority);
            assertEquals(intermediateAuthority.value(),((PkiOperationValue.Text)leafEnvelope.fields().get("authorityId")).value());
            var gatewayRequest=request(realm,"credential.issue",leafEnvelope);
            assertThrows(RuntimeException.class,()->realm.administrativeRequests().submit("ordinary-bypass",gatewayRequest,leafEnvelope,Duration.ofSeconds(30)));
            assertTrue(AdministrativeWorkflowFixture.control(realm).protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,"ordinary-bypass").isEmpty());
            try(var sdk=new AdministrativeRequestCoordinator(realm,AdministrativeWorkflowFixture.control(realm),clock,"https://example.invalid:443")) {
                challenge=sdk.sdkAdmission().challenge(gatewayRequest,leafEnvelope,client.csr(),new byte[32]);
                first=sign(client.primary(),"SHA384withECDSA",challenge.primary().encode());
                second=sign(client.alternative(),"ML-DSA-87",new HybridSdkFrame(2,challenge.primary().fields()).encode());
                var admitted=sdk.sdkAdmission().accept(challenge.intentId(),"sdk-leaf",gatewayRequest,leafEnvelope,Duration.ofSeconds(30),first,second);
                assertEquals(AdministrativeRequest.State.WAITING_APPROVAL,admitted.state());assertTrue(admitted.sdkProof().isPresent());
                assertEquals(AdministrativeRequest.State.WAITING_APPROVAL,sdk.process("sdk-leaf").state());
                assertTrue(sdk.inspect("sdk-leaf","administrator").receipt().isEmpty());
            }
        }
        clock.advance(600); // The accepted 300-second proof must not expire while waiting for human approval.
        var changed=withDefault(original,BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm());
        try(var realm=ServerRealmContext.open(changed.realm(),dependencies(),clock,new java.security.SecureRandom())) {
            var pendingDefault=realm.administrativeRequests().inspect("default-frozen","administrator");approve(realm,pendingDefault);
            var classical=certificate(realm,credential(process(realm.administrativeRequests(),"default-frozen")));
            assertEquals("1.2.840.113549.1.1.12",classical.getSigAlgOID()); // SHA384withRSA, despite the changed creation default.
            try(var sdk=new AdministrativeRequestCoordinator(realm,AdministrativeWorkflowFixture.control(realm),clock,"https://example.invalid:443")) {
                var replay=sdk.sdkAdmission().accept(challenge.intentId(),"sdk-leaf",request(realm,"credential.issue",leafEnvelope),leafEnvelope,Duration.ofSeconds(30),first,second);
                approve(realm,replay);var completed=process(sdk,"sdk-leaf");assertEquals(replay.sdkProof(),completed.sdkProof());
                var leaf=certificate(realm,credential(completed));var intermediate=certificate(realm,intermediateCredential);var rootCertificate=certificate(realm,rootCredential);
                assertEquals(intermediateAuthority,realm.session().repository().credential(credential(completed)).orElseThrow().issuerRef().caId());
                assertEquals(intermediate.getSubjectX500Principal(),leaf.getIssuerX500Principal());
                assertEquals(-1,leaf.getBasicConstraints());
                assertEquals(new javax.security.auth.x500.X500Principal("CN=Alice Example"),leaf.getSubjectX500Principal());
                assertEquals("x509:"+java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(leaf.getEncoded())),credential(completed).value());
                assertDoesNotThrow(()->rootCertificate.verify(rootCertificate.getPublicKey()),"Native root primary signature");
                assertDoesNotThrow(()->intermediate.verify(rootCertificate.getPublicKey()),"Native intermediate primary signature");
                assertDoesNotThrow(()->leaf.verify(intermediate.getPublicKey()),"Native leaf primary signature");
                assertTrue(Pkix.verifyAlternativeSignatureCor3(rootCertificate,alternative(rootCertificate)));
                assertTrue(Pkix.verifyAlternativeSignatureCor3(intermediate,alternative(rootCertificate)));
                assertTrue(Pkix.verifyAlternativeSignatureCor3(leaf,alternative(intermediate)));
                assertFalse(Pkix.verifyAlternativeSignatureCor3(leaf,client.alternative().getPublic()));
                assertArrayEquals(client.alternative().getPublic().getEncoded(),alternativeSpki(leaf));
                var subject=zeroecho.pki.api.hybrid.sdk.HybridSdkValue.decode(challenge.target().field(15)).objectFields();
                assertEquals(Instant.parse(subject.get("notBefore").textValue()),leaf.getNotBefore().toInstant());
                assertEquals(Instant.parse(subject.get("notAfter").textValue()),leaf.getNotAfter().toInstant());
                var predecessor=credential(completed);
                for(String lifecycle:java.util.List.of("credential.renew","credential.reissue","credential.replace")) {
                    boolean replacement=lifecycle.equals("credential.replace");var subjectKeys=replacement?client():client;
                    var lifecycleArgs=replacement?arguments("existingCredentialId",predecessor.value(),"requestId",HybridSdkProofs.parse(subjectKeys.csr()).primary().requestId().value(),"profileId","native-leaf"):arguments("credentialId",predecessor.value());
                    var lifecycleFields=new TreeMap<String,PkiOperationValue>(envelope(lifecycleArgs).fields());lifecycleFields.put("authorityId",new PkiOperationValue.Text(intermediateAuthority.value()));
                    var lifecycleEnvelope=new PkiOperationValue.ObjectValue(lifecycleFields);var lifecycleRequest=request(realm,lifecycle,lifecycleEnvelope);
                    assertThrows(RuntimeException.class,()->sdk.submit("ordinary-"+lifecycle,lifecycleRequest,lifecycleEnvelope,Duration.ofSeconds(30)));
                    if(!replacement) {
                        var wrongKeys=client();
                        assertThrows(RuntimeException.class,()->sdk.sdkAdmission().challenge(lifecycleRequest,lifecycleEnvelope,wrongKeys.csr(),new byte[32]));
                    }
                    var fresh=sdk.sdkAdmission().challenge(lifecycleRequest,lifecycleEnvelope,subjectKeys.csr(),new byte[32]);
                    var target=zeroecho.pki.api.hybrid.sdk.HybridSdkValue.decode(fresh.target().field(17)).objectFields();
                    assertEquals(predecessor.value(),target.get("predecessorId").textValue());assertEquals(lifecycle,target.get("operation").textValue());
                    var firstProof=sign(subjectKeys.primary(),"SHA384withECDSA",fresh.primary().encode());var secondProof=sign(subjectKeys.alternative(),"ML-DSA-87",new HybridSdkFrame(2,fresh.primary().fields()).encode());
                    var pending=sdk.sdkAdmission().accept(fresh.intentId(),lifecycle,lifecycleRequest,lifecycleEnvelope,Duration.ofSeconds(30),firstProof,secondProof);
                    assertEquals(AdministrativeRequest.State.WAITING_APPROVAL,pending.state());assertTrue(pending.receipt().isEmpty());approve(realm,pending);
                    var issued=certificate(realm,credential(process(sdk,lifecycle)));issued.verify(intermediate.getPublicKey());assertTrue(Pkix.verifyAlternativeSignatureCor3(issued,alternative(intermediate)));
                    assertArrayEquals(subjectKeys.primary().getPublic().getEncoded(),issued.getPublicKey().getEncoded());assertArrayEquals(subjectKeys.alternative().getPublic().getEncoded(),alternativeSpki(issued));
                    if(replacement)assertFalse(java.util.Arrays.equals(leaf.getPublicKey().getEncoded(),issued.getPublicKey().getEncoded()));
                }
                assertEquals(4,realm.session().repository().authorities(Optional.empty(),100).size());
            }
        }
    }

    @Test void approvedRootCandidatesActivateExplicitlyAndLostServerAcknowledgmentReconcilesAfterLaterHeadChange(@TempDir Path directory)throws Exception {
        var configuration=withIssuancePolicy(ManagedKeyGenerationIntegrationTest.configuration(directory));
        PkiAdminBootstrap.bootstrap(ManagedKeyGenerationIntegrationTest.withoutSigning(configuration),"administrator","approver","trusted-proxy");
        var clock=new TestClock();String lostId="activation-lost";long firstEpoch;
        try(var realm=ServerRealmContext.open(configuration.realm(),dependencies(),clock,new java.security.SecureRandom())) {
            var keys=realm.session().managedKeyGeneration().orElseThrow();
            var initialKey=keys.generate("7".repeat(64),ManagedKeyGeneration.Parameters.RSA_4096);
            for(var template:BuiltInCertificateProfileCatalog.load(getClass().getClassLoader()))if(template.definition().profileId().equals("root-ca")){realm.session().profiles().importBuiltIn(template);realm.session().profiles().activateProfile("root-ca",1);}
            var initial=submit(realm,"activation-root","ca.create",arguments("formatId","x509","subjectRef","CN=Distributed Example Root","profileId","root-ca","keyRef",initialKey.keyRef().value()));
            approve(realm,initial);var root=authority(realm,credential(process(realm.administrativeRequests(),initial.requestId())));
            for(int generation=0;generation<2;generation++) {
                var old=realm.session().repository().authority(root).orElseThrow();var newKey=keys.generate((generation==0?"8":"9").repeat(64),ManagedKeyGeneration.Parameters.RSA_4096);
                var rotation=submit(realm,"rotation-"+generation,"ca.rotate",arguments("caId",root.value(),"newKeyRef",newKey.keyRef().value()));
                var head=LifecycleProjection.head(((PkiOperationValue.ObjectValue)rotation.envelope().fields().get("arguments")).fields()).orElseThrow();
                approve(realm,rotation);process(realm.administrativeRequests(),rotation.requestId());
                var unchanged=realm.session().repository().authority(root).orElseThrow();assertEquals(old.currentIssuanceIssuerId(),unchanged.currentIssuanceIssuerId());
                var candidate=unchanged.issuerIds().stream().filter(id->!old.issuerIds().contains(id)).findFirst().orElseThrow();
                var inspect=(zeroecho.pki.application.PkiOperationOutcome.Completed)realm.session().operations().execute(new zeroecho.pki.application.PkiOperation.InspectIssuerGeneration(candidate),zeroecho.core.io.CancellationSignal.NONE);
                var fields=inspect.result().fields();assertEquals("PENDING_ACTIVATION",LifecycleProjection.text(fields,"activationState"));
                var candidateCertificate=certificate(realm,new PkiId(LifecycleProjection.text(fields,"downloadCredentialId")));candidateCertificate.verify(candidateCertificate.getPublicKey());
                var args=new TreeMap<>(arguments("caId",root.value(),"issuerId",candidate.value(),"pathId",LifecycleProjection.text(fields,"candidatePathId"),"reason","Distribution completed for Example clients","transitionCommitment",LifecycleProjection.text(fields,"transitionCommitment")).fields());
                args.put("expectedHead",LifecycleProjection.headValue(head));args.put("distributionAcknowledged",new PkiOperationValue.BooleanValue(true));
                var selectEnvelope=envelope(new PkiOperationValue.ObjectValue(args));var selectRequest=request(realm,"issuer.path.select",selectEnvelope);
                var activation=realm.administrativeRequests().submit(generation==0?lostId:"activation-normal",selectRequest,selectEnvelope,Duration.ofSeconds(30));
                assertEquals(AdministrativeRequest.State.WAITING_APPROVAL,activation.state());assertEquals(old.currentIssuanceIssuerId(),realm.session().repository().authority(root).orElseThrow().currentIssuanceIssuerId());approve(realm,activation);
                if(generation==0) {
                    // Exact crash image: real approved gateway commit, but no administrative result acknowledgment.
                    var dispatched=new AdministrativeRequest(activation.requestId(),activation.revision()+1,activation.operation(),activation.envelope(),activation.actor(),activation.scope(),activation.operationCommitment(),activation.profileCommitment(),activation.targetCommitment(),AdministrativeRequest.State.DISPATCHING,activation.createdAt(),clock.instant(),activation.executionTimeoutMillis(),activation.approvalId(),activation.policyCommitment(),Optional.empty(),Optional.empty(),Optional.empty(),activation.sdkProof());
                    var control=AdministrativeWorkflowFixture.control(realm);var prior=control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,lostId).orElseThrow();control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(dispatched),Optional.of(prior.commitment()),Optional.empty(),Optional.empty());
                    var uncertain=realm.administrativeRequests().process(lostId);
                    assertEquals(AdministrativeRequest.State.RECONCILIATION_REQUIRED,uncertain.state());assertEquals("ROOT_ACTIVATION_OUTCOME_UNKNOWN",uncertain.failureCode().orElseThrow());
                    assertEquals(old.currentIssuanceIssuerId(),realm.session().repository().authority(root).orElseThrow().currentIssuanceIssuerId());
                    var selected=(zeroecho.pki.application.PkiOperation.SelectIssuancePath)((AdministrativeOperation.Pki)selectRequest.operation()).operation();
                    var evidence=new zeroecho.pki.api.ca.RootTrustAnchorActivation(1,new PkiId(LifecycleProjection.text(fields,"transitionId")),selected.transitionCommitment().orElseThrow(),head,candidate,selected.pathId(),head.epoch()+1,new PkiId(lostId),activation.actor().principalId(),activation.policyCommitment().orElseThrow(),activation.operationCommitment(),activation.createdAt(),true);
                    var approved=new ServerOperationGateway.Request(selectRequest.realmId(),selectRequest.principalId(),selectRequest.authenticationMode(),selectRequest.transportPrincipalId(),selectRequest.credentialEvidence(),selectRequest.operation(),selectRequest.resource(),selectRequest.relationship(),selectRequest.context(),activation.approvalId(),lostId);
                    var result=assertInstanceOf(ServerOperationGateway.Outcome.Executed.class,realm.gateway().executeRootActivation(approved,evidence,zeroecho.core.io.CancellationSignal.NONE));assertInstanceOf(zeroecho.pki.application.PkiOperationOutcome.Completed.class,result.outcome());
                    assertEquals(ApprovalService.State.EXECUTED,realm.approvals().requireCurrent(activation.approvalId().orElseThrow()).state());
                } else {assertEquals("ACTIVATED",LifecycleProjection.text(process(realm.administrativeRequests(),activation.requestId()).result().orElseThrow().fields(),"activationState"));}
            }
            firstEpoch=2;
        }
        try(var realm=ServerRealmContext.open(configuration.realm(),dependencies(),clock,new java.security.SecureRandom())) {
            var recovered=process(realm.administrativeRequests(),lostId);assertEquals(firstEpoch,((PkiOperationValue.IntegerValue)recovered.result().orElseThrow().fields().get("activationEpoch")).value());
            assertEquals(recovered,realm.administrativeRequests().process(lostId));
        }
    }

    @Test void configuredAdminSdkHttpIssuesAfterApprovalAndRejectsChangedWire(@TempDir Path directory) throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        var original = withIssuancePolicy(ManagedKeyGenerationIntegrationTest.configuration(directory));
        PkiAdminBootstrap.bootstrap(ManagedKeyGenerationIntegrationTest.withoutSigning(original), "administrator", "approver", "trusted-proxy");
        PkiId ca; X509Certificate rootCertificate;
        try (var realm = ServerRealmContext.open(original.realm(), dependencies())) {
            var keys = realm.session().managedKeyGeneration().orElseThrow();
            var primary = keys.generate("8".repeat(64), ManagedKeyGeneration.Parameters.ECDSA_P384);
            var alternative = keys.generate("9".repeat(64), ManagedKeyGeneration.Parameters.ML_DSA_87);
            install(realm, "root-ca", "http-root", new HybridCertificateMode.AltSignature(
                    BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(), alternative.keyRef().value()), IssuanceApprovalRequirement.NONE);
            install(realm, "vpn-client", "http-leaf", HybridCertificateMode.AltSignature.requested(
                    BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm()), IssuanceApprovalRequirement.SINGLE);
            var creation = submit(realm, "http-root", "ca.create", arguments("formatId", "x509", "subjectRef", "CN=HTTP SDK Root",
                    "profileId", "http-root", "keyRef", primary.keyRef().value(), "signatureAlgorithmId", BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm()));
            approve(realm, creation); var credential = credential(process(realm.administrativeRequests(), "http-root"));
            ca = authority(realm, credential); rootCertificate = certificate(realm, credential);
        }
        Instant rootNotBefore = rootCertificate.getNotBefore().toInstant();
        assertFalse(rootNotBefore.isAfter(Instant.now().plusSeconds(1)), "Root validity exceeds inward whole-second boundary");
        while (Instant.now().isBefore(rootNotBefore)) {
            java.util.concurrent.TimeUnit.NANOSECONDS.sleep(Math.max(1, Duration.between(Instant.now(), rootNotBefore).toNanos()));
        }
        rootCertificate.checkValidity();
        var tls = HttpServerTestSupport.tls();
        var transport = HttpServerTestSupport.configuration(directory.resolve("transport"), tls.clientCertificate());
        var old = transport.listener();
        var listener = new PkiServerConfiguration.Listener(old.address(), old.port(), old.tlsProvider(), old.clientCertificateRequired(),
                old.maximumHeaderBytes(), old.maximumBodyBytes(), Optional.of(new PkiServerConfiguration.HybridSdkListener("https://sdk.example.invalid:443")));
        String fingerprint = java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(tls.clientCertificate().getEncoded()));
        var auth = new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(new PkiServerConfiguration.ClientCertificateMapping("sdk-admin", "administrator", Optional.of(fingerprint), Optional.empty(), Optional.empty())),
                List.of(), List.of(), java.util.Set.of(), Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0);
        var config = new PkiServerConfiguration(original.version(), original.serverName(), original.realm(), listener, auth, transport.execution(), transport.runtime());
        try (var http = java.net.http.HttpClient.newBuilder().sslContext(tls.clientContext()).build();
                var server = PkiHttpsServer.start(config, dependencies(), Clock.systemUTC(), HttpServerTestSupport.random(),
                        zeroecho.pki.server.http.TestTlsProvider.class.getClassLoader())) {
            String base = "https://localhost:" + server.address().getPort() + "/admin/v1/hybrid-sdk/v1";
            var capability = http.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(base)).GET().build(), java.net.http.HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200, capability.statusCode());
            assertTrue(new String(capability.body(), java.nio.charset.StandardCharsets.UTF_8).contains("https://sdk.example.invalid:443"));
            var client = client(); var parsed = HybridSdkProofs.parse(client.csr());
            var body = new TreeMap<String, PkiOperationValue>(); body.put("version", new PkiOperationValue.IntegerValue(1));
            body.put("profile", new PkiOperationValue.Text("zeroecho-hybrid-sdk-v1")); body.put("operationId", new PkiOperationValue.Text("credential.issue"));
            body.put("arguments", arguments("issuerCaId", ca.value(), "requestId", parsed.primary().requestId().value(), "profileId", "http-leaf"));
            body.put("requestDer", httpBytes(client.csr())); body.put("clientNonce", httpBytes(new byte[32]));
            assertEquals(400, sdkPost(http, base + "/challenge", new PkiOperationValue.ObjectValue(Map.of())).statusCode());
            var malformed = new TreeMap<>(body); malformed.put("unexpected", new PkiOperationValue.BooleanValue(true));
            assertEquals(400, sdkPost(http, base + "/challenge", new PkiOperationValue.ObjectValue(malformed)).statusCode());
            malformed = new TreeMap<>(body); malformed.put("clientNonce", new PkiOperationValue.Text("AA=="));
            assertEquals(400, sdkPost(http, base + "/challenge", new PkiOperationValue.ObjectValue(malformed)).statusCode());
            malformed = new TreeMap<>(body); malformed.put("clientNonce", httpBytes(new byte[33]));
            assertEquals(400, sdkPost(http, base + "/challenge", new PkiOperationValue.ObjectValue(malformed)).statusCode());
            assertEquals(400, sdkPost(http, base.replace("hybrid-sdk/v1", "hybrid-sdk%2fv1") + "/challenge", new PkiOperationValue.ObjectValue(body)).statusCode());
            var challenged = sdkPost(http, base + "/challenge", new PkiOperationValue.ObjectValue(body));
            assertEquals(200, challenged.statusCode(), new String(challenged.body()));
            var fields = ((PkiOperationValue.ObjectValue) zeroecho.pki.server.http.StrictJson.parse(challenged.body(), 262144)).fields();
            var first = HybridSdkFrame.decode(java.util.Base64.getUrlDecoder().decode(((PkiOperationValue.Text) fields.get("primaryFrame")).value()));
            assertEquals("https://sdk.example.invalid:443", new String(first.field(9), java.nio.charset.StandardCharsets.UTF_8));
            body.remove("clientNonce"); body.put("intentId", fields.get("intentId")); body.put("sdkRequestId", new PkiOperationValue.Text("http-sdk"));
            body.put("primaryProof", httpBytes(sign(client.primary(), "SHA384withECDSA", first.encode())));
            body.put("alternativeProof", httpBytes(sign(client.alternative(), "ML-DSA-87", new HybridSdkFrame(2, first.fields()).encode())));
            byte[] changed = client.csr().clone(); changed[changed.length - 1] ^= 1;
            var changedBody = new TreeMap<>(body); changedBody.put("requestDer", httpBytes(changed));
            assertEquals(409, sdkPost(http, base + "/accept", new PkiOperationValue.ObjectValue(changedBody)).statusCode());
            var accepted = sdkPost(http, base + "/accept", new PkiOperationValue.ObjectValue(body));
            assertEquals(202, accepted.statusCode(), new String(accepted.body()));
            var retained = server.realm().administrativeRequests().inspect("http-sdk", "administrator");
            assertEquals(AdministrativeRequest.State.WAITING_APPROVAL, retained.state()); approve(server.realm(), retained);
            String poll = base.substring(0, base.indexOf("/hybrid-sdk")) + "/requests/http-sdk";
            java.net.http.HttpResponse<byte[]> observed;
            long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
            do {
                observed = http.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(poll)).GET().build(), java.net.http.HttpResponse.BodyHandlers.ofByteArray());
                if (new String(observed.body()).contains("\"state\":\"SUCCEEDED\"")) break;
                Thread.sleep(10);
            } while (System.nanoTime() < deadline);
            assertEquals(200, observed.statusCode()); assertTrue(new String(observed.body()).contains("SUCCEEDED"), new String(observed.body()));
            var completed = server.realm().administrativeRequests().inspect("http-sdk", "administrator");
            var leaf = certificate(server.realm(), credential(completed)); leaf.verify(rootCertificate.getPublicKey());
            assertTrue(Pkix.verifyAlternativeSignatureCor3(leaf, alternative(rootCertificate)));
            assertArrayEquals(client.alternative().getPublic().getEncoded(), alternativeSpki(leaf));
            assertEquals(202, sdkPost(http, base + "/accept", new PkiOperationValue.ObjectValue(body)).statusCode());
        }
    }

    private static PkiOperationValue.Text httpBytes(byte[] value) {
        return new PkiOperationValue.Text(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(value));
    }
    private static java.net.http.HttpResponse<byte[]> sdkPost(java.net.http.HttpClient client, String uri, PkiOperationValue.ObjectValue document) throws Exception {
        return client.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(uri)).header("Content-Type", "application/vnd.zeroecho.hybrid-sdk+json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(zeroecho.pki.server.http.StrictJson.encode(document))).build(),
                java.net.http.HttpResponse.BodyHandlers.ofByteArray());
    }

    private static void install(ServerRealmContext realm,String templateId,String id,HybridCertificateMode mode,IssuanceApprovalRequirement approval) {
        var source=BuiltInCertificateProfileCatalog.load(HybridSdkRealIssuanceTest.class.getClassLoader()).stream().map(t->t.definition()).filter(d->d.profileId().equals(templateId)).findFirst().orElseThrow();
        var definition=new CertificateProfileDefinition(source.certificateType(),id,1,source.formatId(),id,source.maximumValidity(),approval,source.subjectPolicy(),source.certificatePolicy(),source.algorithmBindingPolicy(),source.confirmationPolicy(),mode);
        realm.session().profiles().importProfile(CertificateProfileDocumentCodec.writeCanonical(definition));realm.session().profiles().activateProfile(id,1);
    }
    private static AdministrativeRequest submit(ServerRealmContext realm,String id,String operation,PkiOperationValue.ObjectValue arguments) {
        var envelope=envelope(arguments);return realm.administrativeRequests().submit(id,request(realm,operation,envelope),envelope,Duration.ofSeconds(30));
    }
    private static ServerOperationGateway.Request request(ServerRealmContext realm,String operation,PkiOperationValue.ObjectValue envelope) {
        var decoded=HttpOperationCodec.decode(operation,StrictJson.encode(envelope),262144,realm.configuration().realmId(),realm.gateway()::descriptor);
        var evidence=new CertificateIdentityEvidence(realm.configuration().realmId(),"a".repeat(64),"b".repeat(64),java.util.Set.of("c".repeat(64)),"d".repeat(64));
        return new ServerOperationGateway.Request(realm.configuration().realmId(),"administrator",AdministrativeAuthenticationMode.DIRECT_MTLS,Optional.empty(),Optional.of(evidence),decoded.operation(),decoded.resource(),Permission.Relationship.ANY,decoded.context(),Optional.empty(),operation);
    }
    private static void approve(ServerRealmContext realm,AdministrativeRequest request) {request.approvalId().ifPresent(id->realm.approvals().decide(id,"administrator",ApprovalService.Choice.APPROVE,"Explicit native integration approval"));}
    private static AdministrativeRequest process(AdministrativeRequestCoordinator coordinator,String id)throws Exception {
        long end=System.nanoTime()+Duration.ofSeconds(15).toNanos();AdministrativeRequest result;
        do {result=coordinator.process(id);if(result.terminal())break;Thread.sleep(5);}while(System.nanoTime()<end);
        assertEquals(AdministrativeRequest.State.SUCCEEDED,result.state(),result.failureCode().orElse(result.state().name()));return result;
    }
    private static PkiId credential(AdministrativeRequest result){return new PkiId(((PkiOperationValue.Text)result.result().orElseThrow().fields().get("credentialId")).value());}
    private static PkiId authority(ServerRealmContext realm,PkiId credential) {
        var repository=realm.session().repository();
        var matches=repository.authorities(Optional.empty(),100).stream().filter(ca->ca.issuerIds().stream()
                .anyMatch(id->repository.issuer(id).orElseThrow().credentialId().equals(credential))).toList();
        assertEquals(1,matches.size(),"Exactly one subject authority owns the issued CA credential");
        return matches.getFirst().caId();
    }
    private static X509Certificate certificate(ServerRealmContext realm,PkiId credential)throws Exception{try(var content=realm.session().repository().openCredential(credential);var in=content.openStream()){return Pkix.parseCertificate(in.readAllBytes());}}
    private static byte[] alternativeSpki(X509Certificate certificate){return ASN1OctetString.getInstance(certificate.getExtensionValue("2.5.29.72")).getOctets();}
    private static java.security.PublicKey alternative(X509Certificate certificate)throws Exception{return KeyFactory.getInstance("ML-DSA","BC").generatePublic(new X509EncodedKeySpec(alternativeSpki(certificate)));}
    private static PkiOperationValue.ObjectValue envelope(PkiOperationValue.ObjectValue args){
        var fields=new TreeMap<String,PkiOperationValue>();fields.put("version",new PkiOperationValue.IntegerValue(1));fields.put("arguments",args);
        if(args.fields().containsKey("issuerCaId"))fields.put("authorityId",args.fields().get("issuerCaId"));
        else if(args.fields().containsKey("caId"))fields.put("authorityId",args.fields().get("caId"));
        return new PkiOperationValue.ObjectValue(fields);
    }
    private static PkiOperationValue.ObjectValue arguments(String...values){var result=new TreeMap<String,PkiOperationValue>();for(int i=0;i<values.length;i+=2)result.put(values[i],new PkiOperationValue.Text(values[i+1]));return new PkiOperationValue.ObjectValue(result);}
    private static Client client()throws Exception{
        var ec=KeyPairGenerator.getInstance("EC");ec.initialize(new ECGenParameterSpec("secp384r1"));var primary=ec.generateKeyPair();var ml=KeyPairGenerator.getInstance("ML-DSA","BC");ml.initialize(MLDSAParameterSpec.ml_dsa_87);var alternative=ml.generateKeyPair();
        var extensions=new ExtensionsGenerator();extensions.addExtension(new ASN1ObjectIdentifier("2.5.29.72"),false,alternative.getPublic().getEncoded());extensions.addExtension(new ASN1ObjectIdentifier("2.5.29.17"),false,new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,"spiffe://example.invalid/client/alice")));
        var builder=new JcaPKCS10CertificationRequestBuilder(new javax.security.auth.x500.X500Principal("CN=Alice Example"),primary.getPublic());
        return new Client(primary,alternative,builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,extensions.generate()).build(new JcaContentSignerBuilder("SHA384withECDSA").build(primary.getPrivate())).getEncoded());
    }
    private static byte[] sign(KeyPair key,String algorithm,byte[] bytes)throws Exception{var signature=algorithm.equals("ML-DSA-87")?Signature.getInstance(algorithm,"BC"):Signature.getInstance(algorithm);if(algorithm.equals("ML-DSA-87"))signature.setParameter(new ContextParameterSpec(new byte[0]));signature.initSign(key.getPrivate());signature.update(bytes);return signature.sign();}
    private static PkiSessionRuntimeDependencies dependencies(){return PkiSessionRuntimeDependencies.withKeyringUnlockProvider(()->new KeyringPassword("integration-test-key".toCharArray()));}
    private static PkiServerConfiguration withIssuancePolicy(PkiServerConfiguration source){var r=source.realm();var policies=new java.util.HashMap<>(r.approvalPolicies());policies.put(OperationSecurityDescriptors.ApprovalCategory.ISSUANCE_SINGLE,policies.get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK));var realm=new ServerRealmConfiguration(r.realmId(),r.displayName(),r.confirmationProofPolicy(),r.pkiSessionConfiguration(),r.authorityExposure(),r.authorizationCommitment(),r.approvalCommitment(),ServerRealmConfiguration.extendedApprovalCommitment(policies),r.disclosureCommitment(),r.disclosureDefaults(),r.controlLogPath(),r.controlStoreId(),policies,r.initialAdministratorPrincipalId());return new PkiServerConfiguration(source.version(),source.serverName(),realm,source.listener(),source.authentication(),source.execution(),source.runtime());}
    private static PkiServerConfiguration withDefault(PkiServerConfiguration source,String algorithm){var r=source.realm();var s=r.pkiSessionConfiguration();var old=s.signing().orElseThrow();var signing=new PkiSessionConfiguration.SigningConfiguration(old.provider(),algorithm,old.signingTtl(),old.unlockEnvironmentVariable(),old.topology(),old.pureEdDsaMaximumTbsBytes());var session=new PkiSessionConfiguration(s.version(),s.store(),s.audit(),Optional.of(signing),s.publishers(),s.bindingProviders());var realm=new ServerRealmConfiguration(r.realmId(),r.displayName(),r.confirmationProofPolicy(),session,r.authorityExposure(),r.authorizationCommitment(),r.approvalCommitment(),r.extendedApprovalCommitment(),r.disclosureCommitment(),r.disclosureDefaults(),r.controlLogPath(),r.controlStoreId(),r.approvalPolicies(),r.initialAdministratorPrincipalId());return new PkiServerConfiguration(source.version(),source.serverName(),realm,source.listener(),source.authentication(),source.execution(),source.runtime());}
    private record Client(KeyPair primary,KeyPair alternative,byte[] csr){}
    private static final class TestClock extends Clock{private Instant now=Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);void advance(long seconds){now=now.plusSeconds(seconds);}@Override public Instant instant(){return now;}@Override public ZoneId getZone(){return ZoneOffset.UTC;}@Override public Clock withZone(ZoneId zone){return this;}}
}
