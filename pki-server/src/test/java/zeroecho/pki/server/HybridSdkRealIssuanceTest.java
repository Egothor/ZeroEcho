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
 ******************************************************************************/

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

/**
 * Real native-domain hierarchy and SDK workflow; certificate transport identities are trusted fixtures, not live mTLS.
 */
class HybridSdkRealIssuanceTest {
    /**
     * Exercises real hybrid CA/leaf issuance, preserving normalized creation defaults and frozen absolute validity across approved restart continuation.
     *
     * @param root isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
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

    /**
     * Checks a newly issued root remains a candidate until explicit activation and an uncertain activation acknowledgement reconciles after later head movement.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
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

    /**
     * Checks explicit SDK HTTP capability/shape validation, proof-bound wire equality and approval-gated real issuance.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
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

    /**
     * Checks canonical responder provisioning retains one claim/approval/credential under concurrent replay and permits only explicit next-revision renewal.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void managedResponderProvisioningKeepsOneApprovalAndCredentialAcrossConcurrentReplayAndExplicitRenewal(@TempDir Path directory) throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        var configuration=withIssuancePolicy(ManagedKeyGenerationIntegrationTest.configuration(directory));
        PkiAdminBootstrap.bootstrap(ManagedKeyGenerationIntegrationTest.withoutSigning(configuration),"administrator","approver","trusted-proxy");
        var clock=new TestClock();
        PkiOperationValue.ObjectValue selectedEnvelope;
        String canonical;
        PkiId firstCredential;
        PkiId acceptedOperation;
        try(var realm=ServerRealmContext.open(configuration.realm(),dependencies(),clock,new java.security.SecureRandom())) {
            var keys=realm.session().managedKeyGeneration().orElseThrow();
            var rootKey=keys.generate("1".repeat(64),ManagedKeyGeneration.Parameters.ECDSA_P384);
            var rootAlt=keys.generate("2".repeat(64),ManagedKeyGeneration.Parameters.ML_DSA_87);
            var responderKey=keys.generate("3".repeat(64),ManagedKeyGeneration.Parameters.ECDSA_P384);
            var responderAlt=keys.generate("4".repeat(64),ManagedKeyGeneration.Parameters.ML_DSA_87);
            install(realm,"root-ca","responder-root",new HybridCertificateMode.AltSignature(
                    BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),rootAlt.keyRef().value()),IssuanceApprovalRequirement.NONE);
            var root=submit(realm,"responder-root","ca.create",arguments("formatId","x509","subjectRef","CN=Responder Example Root",
                    "profileId","responder-root","keyRef",rootKey.keyRef().value(),"signatureAlgorithmId",BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm()));
            approve(realm,root);
            var issuerCredential=credential(process(realm.administrativeRequests(),root.requestId()));
            var authority=authority(realm,issuerCredential);
            var ca=realm.session().repository().authority(authority).orElseThrow();
            var path=realm.session().repository().chainPath(ca.issuanceChainPathId()).orElseThrow();
            var source=BuiltInCertificateProfileCatalog.load(getClass().getClassLoader()).stream().map(t->t.definition())
                    .filter(d->d.profileId().equals("vpn-client")).findFirst().orElseThrow();
            var definition=new CertificateProfileDefinition(zeroecho.pki.api.profile.CertificateProfileKind.END_ENTITY,"dedicated-responder",1,
                    source.formatId(),"Dedicated responder",Duration.ofDays(1),IssuanceApprovalRequirement.SINGLE,
                    new zeroecho.pki.api.profile.SubjectPolicy(false,List.of(new zeroecho.pki.api.profile.SubjectRdnRule(
                            zeroecho.pki.api.profile.SubjectRdnType.COMMON_NAME,1,1,128,Optional.empty(),true))),
                    new zeroecho.pki.api.profile.LeafCertificatePolicy(new zeroecho.pki.api.profile.SubjectAlternativeNamePolicy(
                            0,0,List.of(),false,java.util.Set.of(),false,false,false),java.util.Set.of(zeroecho.pki.api.profile.LeafKeyUsage.DIGITAL_SIGNATURE),
                            java.util.Set.of(new zeroecho.pki.api.profile.ExtendedKeyUsageId("1.3.6.1.5.5.7.3.9")),true,false,true,java.util.Set.of("ECDSA")),
                    source.algorithmBindingPolicy(),source.confirmationPolicy(),new HybridCertificateMode.AltSignature(
                            BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),responderAlt.keyRef().value()));
            realm.session().profiles().importProfile(CertificateProfileDocumentCodec.writeCanonical(definition));
            realm.session().profiles().activateProfile("dedicated-responder",1);
            var profile=realm.session().profiles().requireActiveProfile("dedicated-responder").reference();
            var input=new zeroecho.pki.api.issuance.ManagedOcspResponderIssuanceRequest(authority,responderKey.keyRef(),responderAlt.keyRef(),
                    List.of(new zeroecho.pki.api.request.SubjectRdn(zeroecho.pki.api.profile.SubjectRdnType.COMMON_NAME,"Example OCSP Responder")),
                    new zeroecho.pki.api.Validity(clock.instant(),clock.instant().plus(Duration.ofHours(12))),
                    new zeroecho.pki.api.issuance.IssuanceIntent("ignored-caller","0".repeat(64),profile,path.issuerId(),path.pathId(),path.pathCommitment()));
            selectedEnvelope=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),
                    "authorityId",new PkiOperationValue.Text(authority.value()),"arguments",OcspProvisioningProjection.encode(input)));
            var request=request(realm,"ocsp.responder.issue-certificate",selectedEnvelope);
            var admitted=realm.administrativeRequests().submit("caller-one",request,selectedEnvelope,Duration.ofSeconds(30));
            canonical=admitted.requestId();
            assertTrue(canonical.matches("ocsp-prov:[0-9a-f]{64}:r1"));
            assertEquals(AdministrativeRequest.State.WAITING_APPROVAL,admitted.state());
            assertTrue(admitted.receipt().isEmpty());
            try(var executor=java.util.concurrent.Executors.newFixedThreadPool(3)) {
                var envelope=selectedEnvelope;
                var futures=new java.util.ArrayList<java.util.concurrent.Future<AdministrativeRequest>>();
                for(int i=0;i<3;i++){String id="retry-"+i;futures.add(executor.submit(()->realm.administrativeRequests().submit(id,request,envelope,Duration.ofSeconds(10))));}
                for(var future:futures)assertEquals(admitted,future.get());
            }
            var changedArgs=new TreeMap<>(OcspProvisioningProjection.encode(input).fields());
            changedArgs.put("notAfter",new PkiOperationValue.Text(input.validity().notAfter().minusSeconds(1).toString()));
            var changedEnvelope=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),
                    "authorityId",new PkiOperationValue.Text(authority.value()),"arguments",new PkiOperationValue.ObjectValue(changedArgs)));
            assertThrows(AdministrativeRequestCoordinator.ProvisioningConflict.class,()->realm.administrativeRequests().submit("different-date",
                    request(realm,"ocsp.responder.issue-certificate",changedEnvelope),changedEnvelope,Duration.ofSeconds(30)));
            var control=AdministrativeWorkflowFixture.control(realm);
            assertEquals(1,control.protocolRecords(ServerControlStore.OCSP_PROVISIONING,0,100).values().size());
            assertTrue(control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,"caller-one").isEmpty());
            assertEquals(1,control.approvals(0,100).values().stream().filter(a->a.operationId().equals("ocsp.responder.issue-certificate")).count());
            approve(realm,admitted);
            var actual=realm.session().semanticSigning().orElseThrow();
            var accepts=new java.util.concurrent.atomic.AtomicInteger();
            var lostAcknowledgment=(zeroecho.pki.api.SemanticSigningService)java.lang.reflect.Proxy.newProxyInstance(
                    zeroecho.pki.api.SemanticSigningService.class.getClassLoader(),new Class<?>[]{zeroecho.pki.api.SemanticSigningService.class},
                    (proxy,method,parameters)->{
                        if(method.getName().equals("resolve"))throw new zeroecho.pki.api.PkiException("fixture observation unavailable",
                                zeroecho.pki.api.PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);
                        if(method.getName().equals("accept")) {
                            var durable=AdministrativeRequestCodec.decode(control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,canonical).orElseThrow());
                            assertEquals(AdministrativeRequest.State.DISPATCHING,durable.state());assertTrue(durable.receipt().isPresent());
                            assertEquals(ApprovalService.State.EXECUTING,realm.approvals().requireCurrent(admitted.approvalId().orElseThrow()).state());
                            assertEquals(1,accepts.incrementAndGet());
                            try{method.invoke(actual,parameters);}catch(java.lang.reflect.InvocationTargetException failure){throw failure.getCause();}
                            throw new IllegalStateException("fixture lost committed acknowledgment");
                        }
                        try{return method.invoke(actual,parameters);}catch(java.lang.reflect.InvocationTargetException failure){throw failure.getCause();}
                    });
            try(var crashing=new AdministrativeRequestCoordinator(realm,control,clock,()->lostAcknowledgment)) {
                var unknown=crashing.process(canonical);
                assertEquals(AdministrativeRequest.State.DISPATCHING,unknown.state());assertTrue(unknown.receipt().isPresent());
                acceptedOperation=unknown.receipt().orElseThrow().operationId();
                assertEquals("SIGNING_OBSERVATION_UNAVAILABLE",unknown.failureCode().orElseThrow());
                long completedBy=System.nanoTime()+Duration.ofSeconds(15).toNanos();
                while(actual.find(acceptedOperation).orElseThrow().state()!=zeroecho.pki.api.signing.SemanticSigningState.COMPLETED) {
                    if(System.nanoTime()>completedBy)throw new AssertionError("Managed responder real signing did not complete before restart");
                    Thread.sleep(5);
                }
                assertEquals(1,accepts.get());
            }
        }
        try(var realm=ServerRealmContext.open(configuration.realm(),dependencies(),clock,new java.security.SecureRandom())) {
            var replay=realm.administrativeRequests().submit("new-id-after-restart",request(realm,"ocsp.responder.issue-certificate",selectedEnvelope),selectedEnvelope,Duration.ofSeconds(20));
            assertEquals(canonical,replay.requestId());
            var completed=process(realm.administrativeRequests(),canonical);firstCredential=credential(completed);
            assertEquals(acceptedOperation,completed.receipt().orElseThrow().operationId());
            assertEquals(1,AdministrativeWorkflowFixture.control(realm).approvals(0,100).values().stream()
                    .filter(a->a.operationId().equals("ocsp.responder.issue-certificate")).count());
            var credential=realm.session().repository().credential(firstCredential).orElseThrow();
            var ca=realm.session().repository().authority(credential.issuerRef().caId()).orElseThrow();
            var issuer=certificate(realm,realm.session().repository().issuer(ca.currentIssuanceIssuerId()).orElseThrow().credentialId());
            var certificate=certificate(realm,firstCredential);certificate.verify(issuer.getPublicKey());
            assertTrue(Pkix.verifyAlternativeSignatureCor3(certificate,alternative(issuer)));
            assertEquals(List.of("1.3.6.1.5.5.7.3.9"),certificate.getExtendedKeyUsage());
            var again=realm.administrativeRequests().submit("yet-another-id",request(realm,"ocsp.responder.issue-certificate",selectedEnvelope),selectedEnvelope,Duration.ofSeconds(15));
            assertEquals(firstCredential,credential(again));
            var args=new TreeMap<>(((PkiOperationValue.ObjectValue)selectedEnvelope.fields().get("arguments")).fields());
            args.put("expectedPredecessorCredentialId",new PkiOperationValue.Text(firstCredential.value()));
            var renewedEnvelope=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),
                    "authorityId",selectedEnvelope.fields().get("authorityId"),"arguments",new PkiOperationValue.ObjectValue(args)));
            var renewal=realm.administrativeRequests().submit("deliberate-renewal",request(realm,"ocsp.responder.issue-certificate",renewedEnvelope),renewedEnvelope,Duration.ofSeconds(30));
            assertEquals(canonical.substring(0,canonical.length()-1)+"2",renewal.requestId());approve(realm,renewal);
            var renewed=process(realm.administrativeRequests(),renewal.requestId());assertNotEquals(firstCredential,credential(renewed));
            assertEquals(renewed,realm.administrativeRequests().submit("same-predecessor",request(realm,"ocsp.responder.issue-certificate",renewedEnvelope),renewedEnvelope,Duration.ofSeconds(5)));
            assertThrows(AdministrativeRequestCoordinator.ProvisioningConflict.class,()->realm.administrativeRequests().submit("historical-initial",
                    request(realm,"ocsp.responder.issue-certificate",selectedEnvelope),selectedEnvelope,Duration.ofSeconds(30)));
            var row=AdministrativeWorkflowFixture.control(realm).protocolRecords(ServerControlStore.OCSP_PROVISIONING,0,100).values().getFirst();
            var slot=OcspProvisioningSlotCodec.decode(row);assertEquals(credential(renewed),slot.credentialId().orElseThrow());
            assertEquals(2,slot.revision());
        }
        managedResponderHttps(configuration,clock,selectedEnvelope,firstCredential);
    }

    private static void managedResponderHttps(PkiServerConfiguration domain,TestClock clock,
            PkiOperationValue.ObjectValue originalEnvelope,PkiId statusCredential) throws Exception {
        var tls=HttpServerTestSupport.tls();
        var transport=HttpServerTestSupport.configuration(domain.realm().controlLogPath().getParent().resolve("ocsp-wire-transport"),tls.clientCertificate());
        String fingerprint=java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(tls.clientCertificate().getEncoded()));
        var auth=new PkiServerConfiguration.Authentication(AdministrativeAuthenticationMode.DIRECT_MTLS,
                List.of(new PkiServerConfiguration.ClientCertificateMapping("wire-admin","administrator",Optional.of(fingerprint),Optional.empty(),Optional.empty())),
                List.of(),List.of(),java.util.Set.of(),Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty(),0,0);
        var publicListener=new PkiServerConfiguration.PublicListener(java.net.InetAddress.getByName("127.0.0.1"),0,
                Optional.of(transport.listener().tlsProvider()),false,auth,16384,65536,transport.execution(),Duration.ofSeconds(20),
                Duration.ofMinutes(5),Duration.ofSeconds(30),true,Optional.empty(),Optional.of(new PkiServerConfiguration.HybridSdkListener("https://ocsp.example.invalid:443")));
        var config=new PkiServerConfiguration(domain.version(),domain.serverName(),domain.realm(),transport.listener(),auth,
                transport.execution(),transport.runtime(),Optional.of(publicListener));
        byte[] nativeRequest;
        try(var http=java.net.http.HttpClient.newBuilder().sslContext(tls.clientContext()).build();
                var anonymous=java.net.http.HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
                var server=PkiHttpsServer.start(config,dependencies(),clock,HttpServerTestSupport.random(),zeroecho.pki.server.http.TestTlsProvider.class.getClassLoader())) {
            String admin="https://localhost:"+server.address().getPort()+"/admin/v1/";
            String publicBase="https://localhost:"+server.publicAddress().orElseThrow().getPort()+"/ocsp/wire-responder";
            var catalog=http.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(admin+"operations")).GET().build(),java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(200,catalog.statusCode());assertTrue(catalog.body().contains("ocsp.responder.issue-certificate"));
            var row=AdministrativeWorkflowFixture.control(server.realm()).protocolRecords(ServerControlStore.OCSP_PROVISIONING,0,100).values().getFirst();
            var old=OcspProvisioningSlotCodec.decode(row);
            var args=new TreeMap<>(((PkiOperationValue.ObjectValue)originalEnvelope.fields().get("arguments")).fields());
            args.put("expectedPredecessorCredentialId",new PkiOperationValue.Text(old.credentialId().orElseThrow().value()));
            var submittedBody=new TreeMap<String,PkiOperationValue>();submittedBody.put("version",new PkiOperationValue.IntegerValue(1));
            submittedBody.put("requestId",new PkiOperationValue.Text("wire-provision"));submittedBody.put("operation",new PkiOperationValue.Text("ocsp.responder.issue-certificate"));
            submittedBody.put("authorityId",originalEnvelope.fields().get("authorityId"));submittedBody.put("arguments",new PkiOperationValue.ObjectValue(args));
            var accepted=jsonPost(http,admin+"requests",new PkiOperationValue.ObjectValue(submittedBody));
            assertEquals(202,accepted.statusCode(),new String(accepted.body()));
            String canonical=accepted.headers().firstValue("Location").orElseThrow().substring("/admin/v1/requests/".length());
            assertTrue(canonical.endsWith(":r3"));assertNotEquals("wire-provision",canonical);
            var pending=server.realm().administrativeRequests().inspect(canonical,"administrator");
            assertEquals(AdministrativeRequest.State.WAITING_APPROVAL,pending.state());assertTrue(pending.receipt().isEmpty());
            var decision=envelope(arguments("approvalId",pending.approvalId().orElseThrow(),"justification","Explicit responder renewal for HTTPS verification"));
            assertEquals(200,jsonPost(http,admin+"operations/security.approval.approve",decision).statusCode());
            var completed=process(server.realm().administrativeRequests(),canonical);var responderCredential=credential(completed);
            var duplicate=new TreeMap<>(submittedBody);duplicate.put("requestId",new PkiOperationValue.Text("wire-different-caller"));
            var repeated=jsonPost(http,admin+"requests",new PkiOperationValue.ObjectValue(duplicate));
            assertEquals(202,repeated.statusCode());assertEquals(accepted.headers().firstValue("Location"),repeated.headers().firstValue("Location"));
            var changed=new TreeMap<>(args);changed.put("notAfter",new PkiOperationValue.Text(Instant.parse(((PkiOperationValue.Text)args.get("notAfter")).value()).minusSeconds(1).toString()));
            duplicate.put("arguments",new PkiOperationValue.ObjectValue(changed));
            var conflict=jsonPost(http,admin+"requests",new PkiOperationValue.ObjectValue(duplicate));
            assertEquals(409,conflict.statusCode(),new String(conflict.body()));assertTrue(new String(conflict.body()).contains("OCSP_PROVISIONING_TARGET_CONFLICT"));
            assertEquals(accepted.headers().firstValue("Location"),conflict.headers().firstValue("Location"));
            var input=OcspProvisioningProjection.decode(args);
            var registry=server.realm().session().algorithmBindings().commitment();
            var registration=new TreeMap<String,PkiOperationValue>(arguments("responderId","wire-responder","alias","wire-responder", "authorityId",input.authorityId().value(),
                    "issuerId",input.intent().expectedIssuerId().value(),"signingMode","DELEGATED_RESPONDER","responderCredentialId",responderCredential.value(),
                    "signingKeyRef",input.primaryKeyRef().value(),"chainPathId",input.intent().expectedChainPathId().value(),"signatureAlgorithm",BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),
                    "signatureBindingCommitment",registry,"responderIdForm","BY_KEY","noncePolicy","OPTIONAL_ECHO","requestAuthenticationMode","UNSIGNED_ONLY").fields());
            registration.put("responseValidityMillis",new PkiOperationValue.IntegerValue(300000));registration.put("maximumNonceBytes",new PkiOperationValue.IntegerValue(64));
            registration.put("acceptedHashes",new PkiOperationValue.ListValue(List.of(new PkiOperationValue.Text("SHA256"))));
            registration.put("maximumRequestBytes",new PkiOperationValue.IntegerValue(16384));registration.put("maximumEntries",new PkiOperationValue.IntegerValue(16));
            registration.put("cacheLifetimeMillis",new PkiOperationValue.IntegerValue(30000));
            registration.put("hybridSdk",arguments("profile","zeroecho-hybrid-sdk-v1","alternativeKeyRef",input.alternativeKeyRef().value(),
                    "alternativeSignatureAlgorithm",BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),"alternativeSignatureBindingCommitment",registry));
            var registerBody=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),"requestId",new PkiOperationValue.Text("wire-register"),
                    "operation",new PkiOperationValue.Text("ocsp.responder.register"),"arguments",new PkiOperationValue.ObjectValue(registration)));
            var registered=jsonPost(http,admin+"requests",registerBody);assertEquals(202,registered.statusCode(),new String(registered.body()));
            var registerPending=server.realm().administrativeRequests().inspect("wire-register","administrator");
            if(registerPending.approvalId().isPresent())assertEquals(200,jsonPost(http,admin+"operations/security.approval.approve",
                    envelope(arguments("approvalId",registerPending.approvalId().orElseThrow(),"justification","Enable dedicated SDK OCSP responder"))).statusCode());
            process(server.realm().administrativeRequests(),"wire-register");
            var activateBody=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),"requestId",new PkiOperationValue.Text("wire-activate"),
                    "operation",new PkiOperationValue.Text("ocsp.responder.activate"),"arguments",arguments("responderId","wire-responder")));
            var activationResponse=jsonPost(http,admin+"requests",activateBody);assertEquals(202,activationResponse.statusCode(),new String(activationResponse.body()));
            var activation=server.realm().administrativeRequests().inspect("wire-activate","administrator");
            if(activation.approvalId().isPresent())assertEquals(200,jsonPost(http,admin+"operations/security.approval.approve",
                    envelope(arguments("approvalId",activation.approvalId().orElseThrow(),"justification","Activate dedicated SDK responder"))).statusCode());
            process(server.realm().administrativeRequests(),activation.requestId());
            var capability=anonymous.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(publicBase+"/hybrid-sdk/v1")).GET().build(),java.net.http.HttpResponse.BodyHandlers.ofString());
            assertEquals(200,capability.statusCode(),capability.body());assertTrue(capability.body().contains("https://ocsp.example.invalid:443"));
            assertFalse(capability.body().contains("responderCredentialId"));assertFalse(capability.body().contains("KeyRef"));
            var issuerCredential=server.realm().session().repository().issuer(input.intent().expectedIssuerId()).orElseThrow().credentialId();
            var issuer=certificate(server.realm(),issuerCredential);var queried=certificate(server.realm(),statusCredential);
            var digest=new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build().get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256));
            var builder=new org.bouncycastle.cert.ocsp.OCSPReqBuilder();builder.addRequest(new org.bouncycastle.cert.ocsp.CertificateID(digest,new org.bouncycastle.cert.jcajce.JcaX509CertificateHolder(issuer),queried.getSerialNumber()));
            nativeRequest=builder.build().getEncoded();byte[] nonce=new byte[32];nonce[0]=7;
            var query=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),"profile",new PkiOperationValue.Text("zeroecho-hybrid-sdk-v1"),
                    "requestDer",httpBytes(nativeRequest),"clientNonce",httpBytes(nonce)));
            var response=sdkPost(anonymous,publicBase+"/hybrid-sdk/v1",query);assertEquals(200,response.statusCode(),new String(response.body()));
            assertEquals("no-store",response.headers().firstValue("Cache-Control").orElseThrow());
            var evidence=ocspEvidence(response.body());
            var responder=certificate(server.realm(),responderCredential);
            var service=server.realm().session().ocsp().orElseThrow();
            var binding=service.captureSdkResponderBinding(server.realm().configuration().realmId().value(),"https://ocsp.example.invalid:443",input.authorityId(),input.intent().expectedIssuerId(),
                    responderCredential,input.intent().expectedChainPathId(),new zeroecho.pki.application.OcspResponseService.SdkSigningRole(input.primaryKeyRef(),BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm(),Optional.empty()),
                    new zeroecho.pki.application.OcspResponseService.SdkSigningRole(input.alternativeKeyRef(),BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE.canonicalForm(),Optional.empty()),zeroecho.pki.application.OcspResponseService.ResponderId.BY_KEY,zeroecho.core.io.CancellationSignal.NONE);
            var roles=zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(Map.of("primary",ocspRole(responder.getPublicKey().getEncoded(),false),"alternative",ocspRole(alternativeSpki(responder),true)));
            var trusted=new zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.TrustedContext(binding.realmId(),binding.canonicalOrigin(),binding.authorityId(),binding.issuerId(),binding.chainPathId(),
                    binding.pathCommitment(),binding.issuerBindingCommitment(),nativeRequest,nonce,List.of(issuer.getEncoded()),binding.issuerCertificateBaselines(),responder.getEncoded(),roles,clock.instant());
            var verified=zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.verify(evidence,trusted);
            assertEquals("GOOD",verified.statuses().listValues().getFirst().objectFields().get("status").textValue());
            byte[] invalid=evidence.alternativeSignature();invalid[0]^=1;
            var tampered=new zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence(evidence.primaryResponseDer(),evidence.responderChain(),evidence.primaryFrame(),evidence.alternativeFrame(),evidence.primarySignature(),invalid);
            assertThrows(IllegalArgumentException.class,()->zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.verify(tampered,trusted));
            server.realm().session().revocations().revokePermanently(new zeroecho.pki.api.revocation.RevocationCommand.RevokePermanently(statusCredential,
                    zeroecho.pki.api.revocation.RevocationReason.KEY_COMPROMISE,new zeroecho.pki.impl.core.attr.SimpleAttributeSet(List.of())));
            var revoked=sdkPost(anonymous,publicBase+"/hybrid-sdk/v1",query);assertEquals(200,revoked.statusCode(),new String(revoked.body()));
            var revokedProjection=zeroecho.pki.api.hybrid.sdk.SdkOcspEvidenceVerifier.verify(ocspEvidence(revoked.body()),trusted);
            assertEquals("REVOKED",revokedProjection.statuses().listValues().getFirst().objectFields().get("status").textValue());
            var malformed=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),"profile",new PkiOperationValue.Text("zeroecho-hybrid-sdk-v1"),"requestDer",httpBytes(nativeRequest),"clientNonce",new PkiOperationValue.Text("AA==")));
            assertEquals(400,sdkPost(anonymous,publicBase+"/hybrid-sdk/v1",malformed).statusCode());
            var nativeResponse=anonymous.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(publicBase)).header("Content-Type","application/ocsp-request")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(nativeRequest)).build(),java.net.http.HttpResponse.BodyHandlers.ofByteArray());
            assertEquals(200,nativeResponse.statusCode());assertTrue(Pkix.parseOcspResponse(nativeResponse.body()).verifySignature(responder.getPublicKey()));
        }
        var disabled=new PkiServerConfiguration.PublicListener(publicListener.address(),0,publicListener.tlsProvider(),false,auth,publicListener.maximumHeaderBytes(),publicListener.maximumBodyBytes(),
                publicListener.execution(),publicListener.maximumStreamDuration(),publicListener.publicImmutableCache(),publicListener.publicAliasCache(),true);
        var nativeConfig=new PkiServerConfiguration(domain.version(),domain.serverName(),domain.realm(),transport.listener(),auth,transport.execution(),transport.runtime(),Optional.of(disabled));
        try(var anonymous=java.net.http.HttpClient.newBuilder().sslContext(tls.anonymousContext()).build();
                var server=PkiHttpsServer.start(nativeConfig,dependencies(),clock,HttpServerTestSupport.random(),zeroecho.pki.server.http.TestTlsProvider.class.getClassLoader())) {
            String base="https://localhost:"+server.publicAddress().orElseThrow().getPort()+"/ocsp/wire-responder";
            assertEquals(404,anonymous.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(base+"/hybrid-sdk/v1")).GET().build(),java.net.http.HttpResponse.BodyHandlers.ofByteArray()).statusCode());
            assertEquals(200,anonymous.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(base)).header("Content-Type","application/ocsp-request")
                    .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(nativeRequest)).build(),java.net.http.HttpResponse.BodyHandlers.ofByteArray()).statusCode());
        }
    }

    private static java.net.http.HttpResponse<byte[]> jsonPost(java.net.http.HttpClient client,String uri,PkiOperationValue.ObjectValue body) throws Exception {
        return client.send(java.net.http.HttpRequest.newBuilder(java.net.URI.create(uri)).header("Content-Type","application/json")
                .POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(StrictJson.encode(body))).build(),java.net.http.HttpResponse.BodyHandlers.ofByteArray());
    }
    private static zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence ocspEvidence(byte[] bytes) {
        var fields=((PkiOperationValue.ObjectValue)StrictJson.parse(bytes,8388608)).fields();
        java.util.function.Function<String,byte[]> decode=key->java.util.Base64.getUrlDecoder().decode(((PkiOperationValue.Text)fields.get(key)).value());
        var chain=((PkiOperationValue.ListValue)fields.get("responderChain")).values().stream().map(v->java.util.Base64.getUrlDecoder().decode(((PkiOperationValue.Text)v).value())).toList();
        return new zeroecho.pki.api.hybrid.sdk.SdkOcspEvidence(decode.apply("primaryResponseDer"),chain,HybridSdkFrame.decode(decode.apply("primaryFrame")),HybridSdkFrame.decode(decode.apply("alternativeFrame")),decode.apply("primarySignature"),decode.apply("alternativeSignature"));
    }
    private static zeroecho.pki.api.hybrid.sdk.HybridSdkValue ocspRole(byte[] spki,boolean alternative) {
        return zeroecho.pki.api.hybrid.sdk.HybridSdkValue.object(Map.of("spki",zeroecho.pki.api.hybrid.sdk.HybridSdkValue.bytes(spki),
                "publicKeyAlgorithm",zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text((alternative?BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY:BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY).canonicalForm()),
                "signatureAlgorithm",zeroecho.pki.api.hybrid.sdk.HybridSdkValue.text((alternative?BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE:BootstrapAlgorithmIdentities.ECDSA_SHA384).canonicalForm()),
                "algorithmIdentifier",zeroecho.pki.api.hybrid.sdk.HybridSdkValue.bytes(alternative?HybridSdkFrame.alternativeAlgorithm():HybridSdkFrame.primaryAlgorithm())));
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
