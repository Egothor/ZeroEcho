package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.hybrid.sdk.HybridSdkFrame;
import zeroecho.pki.api.hybrid.sdk.HybridSdkValue;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/**
 * Trusted-context fixtures exercise the real durable gate; they do not claim live issuer resolution or issuance.
 */
class HybridSdkAdmissionServiceTest {
    /**
     * Checks malformed proofs/original-wire mismatch cannot create approvals, while exact accepted admission survives restart and later challenge expiry.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void validatesBeforeApprovalAndRetainsOneConsumedReceiptAcrossRestartAndExpiry(@TempDir Path directory) throws Exception {
        var config=PkiAdminBootstrapTest.configuration(directory);
        PkiAdminBootstrap.bootstrap(config,"administrator","approver","trusted-proxy");
        var clock=new TestClock(); var keys=keys();
        String intent;
        byte[] primary,alternative;
        try(var realm=ServerRealmContext.open(config.realm(),PkiSessionRuntimeDependencies.none())) {
            var control=AdministrativeWorkflowFixture.control(realm);
            var refuseFresh = new java.util.concurrent.atomic.AtomicBoolean();
            try(var coordinator=conditionalCoordinator(realm,control,clock,refuseFresh)) {
                var request=request(realm); var challenge=coordinator.sdkAdmission().challenge(request,envelope(),keys.csr(),new byte[32]);
                intent=challenge.intentId();primary=sign(keys.primary(),"SHA384withECDSA",challenge.primary().encode());
                alternative=sign(keys.alternative(),"ML-DSA-87",new HybridSdkFrame(2,challenge.primary().fields()).encode());
                byte[] corrupt=alternative.clone();corrupt[0]^=1;
                assertThrows(RuntimeException.class,()->coordinator.sdkAdmission().accept(intent,"sdk-one",request,envelope(),Duration.ofSeconds(30),primary,corrupt));
                assertTrue(control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,"sdk-one").isEmpty());
                assertTrue(control.approvals(0,10).values().isEmpty());
                byte[] changedDer = keys.csr().clone(); changedDer[changedDer.length - 1] ^= 1;
                assertThrows(AdministrativeRequestCoordinator.Conflict.class, () -> coordinator.sdkAdmission().accept(
                        intent, "sdk-one", request, envelope(), Duration.ofSeconds(30), changedDer, primary, alternative));
                var retained=coordinator.sdkAdmission().accept(intent,"sdk-one",request,envelope(),Duration.ofSeconds(30),primary,alternative);
                assertEquals(AdministrativeRequest.State.WAITING_APPROVAL,retained.state());
                assertTrue(retained.receipt().isEmpty());
                assertEquals(ApprovalService.State.PENDING,control.approvals(0,10).values().getFirst().state());
                assertEquals(intent,retained.sdkProof().orElseThrow().intentId());
                assertEquals(1,control.approvals(0,10).values().size());
                assertEquals(retained,AdministrativeRequestCodec.decode(AdministrativeRequestCodec.encode(retained)));
                assertEquals(2,((PkiOperationValue.IntegerValue)((PkiOperationValue.ObjectValue)zeroecho.pki.server.http.StrictJson.parse(
                        AdministrativeRequestCodec.encode(retained).payload(),524288)).fields().get("version")).value());
                assertThrows(AdministrativeRequestCoordinator.Conflict.class,()->coordinator.sdkAdmission().accept(intent,"sdk-other",request,envelope(),Duration.ofSeconds(30),primary,alternative));
                clock.advance(600);
                refuseFresh.set(true); // Consumed READ replay must not revisit current issuer/policy resolution.
                assertEquals(retained,coordinator.sdkAdmission().accept(intent,"sdk-one",request,envelope(),Duration.ofSeconds(30),primary,alternative));
            }
        }
        try(var realm=ServerRealmContext.open(config.realm(),PkiSessionRuntimeDependencies.none())) {
            var control=AdministrativeWorkflowFixture.control(realm);
            try(var coordinator=coordinator(realm,control,clock)) {
                var replay=coordinator.sdkAdmission().accept(intent,"sdk-one",request(realm),envelope(),Duration.ofSeconds(30),primary,alternative);
                assertEquals(intent,replay.sdkProof().orElseThrow().intentId());assertEquals(1,control.approvals(0,10).values().size());
                // The production-default resolver is unsupported; recovery cannot turn a fixture admission into issuance.
                var failed=realm.administrativeRequests().process("sdk-one");
                assertEquals(AdministrativeRequest.State.FAILED,failed.state());
                assertEquals(replay.sdkProof(),failed.sdkProof());
            }
        }
    }

    /**
     * Checks invalid original proof, absent validated identity, denied/changed context and expired challenge fail before durable admission.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void rejectsInvalidOriginalProofMissingIdentityChangedContextAndExpiredChallengesBeforeAdmission(@TempDir Path directory)throws Exception {
        var config=PkiAdminBootstrapTest.configuration(directory);PkiAdminBootstrap.bootstrap(config,"administrator","approver","trusted-proxy");
        var clock=new TestClock();var keys=keys();
        try(var realm=ServerRealmContext.open(config.realm(),PkiSessionRuntimeDependencies.none())) {
            var control=AdministrativeWorkflowFixture.control(realm);
            try(var coordinator=coordinator(realm,control,clock)) {
                var request=request(realm);byte[] bad=keys.csr().clone();bad[bad.length-1]^=1;
                assertThrows(RuntimeException.class,()->coordinator.sdkAdmission().challenge(request,envelope(),bad,new byte[32]));
                assertTrue(control.protocolRecords(ServerControlStore.HYBRID_SDK_INTENT,0,10).values().isEmpty());
                var noEvidence=new ServerOperationGateway.Request(request.realmId(),request.principalId(),request.authenticationMode(),Optional.empty(),Optional.empty(),
                        request.operation(),request.resource(),request.relationship(),request.context(),Optional.empty(),"fixture");
                assertThrows(SecurityException.class,()->coordinator.sdkAdmission().challenge(noEvidence,envelope(),keys.csr(),new byte[32]));
                try(var denied=new AdministrativeRequestCoordinator(realm,control,clock,()->{throw new AssertionError("must not sign");},"https://example.invalid:443",(r,e,subject)->{
                    var value=context(realm,r,e);var admission=value.admission();
                    return new HybridSdkAdmissionService.Context(new ServerOperationGateway.Admission(admission.request(),admission.commitment(),admission.policy(),
                            new AuthorizationEngine.Decision(AuthorizationEngine.Code.NO_MATCHING_GRANT,false)),value.target());
                })) {
                    assertThrows(IllegalArgumentException.class,()->denied.sdkAdmission().challenge(request,envelope(),keys.csr(),new byte[32]));
                }
                assertTrue(control.protocolRecords(ServerControlStore.HYBRID_SDK_INTENT,0,10).values().isEmpty());
                var challenge=coordinator.sdkAdmission().challenge(request,envelope(),keys.csr(),new byte[32]);
                byte[] first=sign(keys.primary(),"SHA384withECDSA",challenge.primary().encode());
                byte[] second=sign(keys.alternative(),"ML-DSA-87",new HybridSdkFrame(2,challenge.primary().fields()).encode());
                var changed=withEvidence(request,new CertificateIdentityEvidence(request.realmId(),"b".repeat(64),"c".repeat(64),Set.of("d".repeat(64)),"e".repeat(64)));
                assertThrows(SecurityException.class,()->coordinator.sdkAdmission().accept(challenge.intentId(),"changed",changed,envelope(),Duration.ofSeconds(30),first,second));
                clock.advance(-1);
                assertThrows(RuntimeException.class,()->coordinator.sdkAdmission().accept(challenge.intentId(),"rollback",request,envelope(),Duration.ofSeconds(30),first,second));
                clock.advance(301);
                assertThrows(RuntimeException.class,()->coordinator.sdkAdmission().accept(challenge.intentId(),"expired",request,envelope(),Duration.ofSeconds(30),first,second));
                assertTrue(control.approvals(0,10).values().isEmpty());
                assertTrue(control.protocolRecords(ServerControlStore.ADMINISTRATIVE_REQUEST,0,10).values().isEmpty());
            }
        }
    }

    /**
     * Checks atomic intent consumption under concurrent replay and lost acknowledgement without generating another approval.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void concurrentRetriesConsumeOnceAndAnAcknowledgementLossReconcilesWithoutAnotherApproval(@TempDir Path directory)throws Exception {
        var config=PkiAdminBootstrapTest.configuration(directory);PkiAdminBootstrap.bootstrap(config,"administrator","approver","trusted-proxy");
        var clock=new TestClock();var keys=keys();
        try(var realm=ServerRealmContext.open(config.realm(),PkiSessionRuntimeDependencies.none())) {
            var base=AdministrativeWorkflowFixture.control(realm);
            var metadataField=ServerControlStore.class.getDeclaredField("metadata");metadataField.setAccessible(true);
            var metadata=(TransactionalMetadataStore)metadataField.get(base);var loseAcknowledgement=new AtomicBoolean();var failBeforeCommit=new AtomicBoolean();
            var borrowed=(TransactionalMetadataStore)Proxy.newProxyInstance(TransactionalMetadataStore.class.getClassLoader(),new Class<?>[]{TransactionalMetadataStore.class},(proxy,method,arguments)->{
                Object result=invoke(metadata,method,arguments);
                if(method.getName().equals("beginTransaction")) {
                    var transaction=(MetadataTransaction)result;
                    return Proxy.newProxyInstance(MetadataTransaction.class.getClassLoader(),new Class<?>[]{MetadataTransaction.class},(p,m,a)->{
                        if(m.getName().equals("commit")&&failBeforeCommit.compareAndSet(true,false))throw new IllegalStateException("fixture before commit");
                        Object returned=invoke(transaction,m,a);
                        if(m.getName().equals("commit")&&loseAcknowledgement.compareAndSet(true,false))throw new IllegalStateException("fixture lost committed acknowledgement");
                        return returned;
                    });
                }
                return result;
            });
            // This store borrows the realm-owned metadata; only the realm closes that underlying resource.
            var control=new ServerControlStore(borrowed);
            try(var coordinator=coordinator(realm,control,clock)) {
                var request=request(realm);var challenge=coordinator.sdkAdmission().challenge(request,envelope(),keys.csr(),new byte[32]);
                byte[] first=sign(keys.primary(),"SHA384withECDSA",challenge.primary().encode());
                byte[] second=sign(keys.alternative(),"ML-DSA-87",new HybridSdkFrame(2,challenge.primary().fields()).encode());
                failBeforeCommit.set(true);
                assertThrows(IllegalStateException.class,()->coordinator.sdkAdmission().accept(challenge.intentId(),"lost",request,envelope(),Duration.ofSeconds(30),first,second));
                assertTrue(control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,"lost").isEmpty());
                assertTrue(control.approvals(0,10).values().isEmpty());
                loseAcknowledgement.set(true);
                assertThrows(IllegalStateException.class,()->coordinator.sdkAdmission().accept(challenge.intentId(),"lost",request,envelope(),Duration.ofSeconds(30),first,second));
                assertTrue(control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,"lost").isPresent());
                var ready=new CountDownLatch(1);
                try(var pool=Executors.newFixedThreadPool(2)) {
                    var one=pool.submit(()->{ready.await();return coordinator.sdkAdmission().accept(challenge.intentId(),"lost",request,envelope(),Duration.ofSeconds(30),first,second);});
                    var two=pool.submit(()->{ready.await();return coordinator.sdkAdmission().accept(challenge.intentId(),"lost",request,envelope(),Duration.ofSeconds(30),first,second);});
                    ready.countDown();assertEquals(one.get(5,TimeUnit.SECONDS),two.get(5,TimeUnit.SECONDS));
                }
                assertEquals(1,control.approvals(0,10).values().size());assertEquals(1,control.protocolRecords(ServerControlStore.ADMINISTRATIVE_REQUEST,0,10).values().size());
                var racing=coordinator.sdkAdmission().challenge(request,envelope(),keys.csr(),new byte[32]);
                byte[] racingPrimary=sign(keys.primary(),"SHA384withECDSA",racing.primary().encode());
                byte[] racingAlternative=sign(keys.alternative(),"ML-DSA-87",new HybridSdkFrame(2,racing.primary().fields()).encode());
                var begin=new CountDownLatch(1);
                try(var pool=Executors.newFixedThreadPool(2)) {
                    var one=pool.submit(()->{begin.await();return coordinator.sdkAdmission().accept(racing.intentId(),"raced",request,envelope(),Duration.ofSeconds(30),racingPrimary,racingAlternative);});
                    var two=pool.submit(()->{begin.await();return coordinator.sdkAdmission().accept(racing.intentId(),"raced",request,envelope(),Duration.ofSeconds(30),racingPrimary,racingAlternative);});
                    begin.countDown();assertEquals(one.get(5,TimeUnit.SECONDS),two.get(5,TimeUnit.SECONDS));
                }
                assertEquals(2,control.approvals(0,10).values().size());
                var retained=coordinator.inspect("lost","administrator");
                var stripped=new AdministrativeRequest(retained.requestId(),retained.revision()+1,retained.operation(),retained.envelope(),retained.actor(),retained.scope(),retained.operationCommitment(),retained.profileCommitment(),retained.targetCommitment(),retained.state(),retained.createdAt(),retained.updatedAt(),retained.executionTimeoutMillis(),retained.approvalId(),retained.policyCommitment(),retained.receipt(),retained.result(),retained.failureCode());
                assertThrows(IllegalStateException.class,()->control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(stripped),Optional.of(AdministrativeRequestCodec.encode(retained).commitment()),Optional.empty(),Optional.empty()));
                var receipt=zeroecho.pki.api.signing.SigningAcceptanceReceipt.parse(new PkiId("signing:fixture-accepted"),"accept-sign:v3:"+"7".repeat(64));
                var accepted=new AdministrativeRequest(retained.requestId(),retained.revision()+1,retained.operation(),retained.envelope(),retained.actor(),retained.scope(),retained.operationCommitment(),retained.profileCommitment(),retained.targetCommitment(),AdministrativeRequest.State.RUNNING,retained.createdAt(),retained.updatedAt(),retained.executionTimeoutMillis(),retained.approvalId(),retained.policyCommitment(),Optional.of(receipt),Optional.empty(),Optional.empty(),retained.sdkProof());
                control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(accepted),Optional.of(AdministrativeRequestCodec.encode(retained).commitment()),Optional.empty(),Optional.empty());
                realm.setPrincipalEnabled("administrator",false,"approver");
                var observed=new java.util.concurrent.atomic.AtomicInteger();
                var service=(zeroecho.pki.api.SemanticSigningService)Proxy.newProxyInstance(zeroecho.pki.api.SemanticSigningService.class.getClassLoader(),new Class<?>[]{zeroecho.pki.api.SemanticSigningService.class},(proxy,method,arguments)->{
                    if(method.getName().equals("resolve")) {observed.incrementAndGet();assertEquals(receipt,arguments[0]);return zeroecho.pki.api.signing.SigningAcceptanceResolution.CONFLICT;}
                    throw new AssertionError("observation must not sign or submit another operation");
                });
                // Current actor is disabled and the resolver is unsupported: neither may hide an already accepted receipt's outcome.
                try(var restarted=new AdministrativeRequestCoordinator(realm,control,clock,()->service)) {
                    var completed=restarted.process("lost");
                    assertEquals(AdministrativeRequest.State.RECONCILIATION_REQUIRED,completed.state());
                    assertEquals("SIGNING_RECEIPT_CONFLICT",completed.failureCode().orElseThrow());
                    assertEquals(accepted.sdkProof(),completed.sdkProof());assertEquals(accepted.receipt(),completed.receipt());assertEquals(1,observed.get());
                }
            }
        }
    }

    /**
     * Checks golden ordinary version-one encoding remains stable while unknown SDK versions, absent resolver capability and oversized intents are rejected.
     *
     * @param directory isolated JUnit-managed root for filesystem fixtures
     *
     * @throws Exception if test fixture setup or execution fails
     */
    @Test void ordinaryCodecRemainsVersionOneAndUnknownSdkVersionsAndOversizedIntentsAreRejected(@TempDir Path directory)throws Exception {
        var config=PkiAdminBootstrapTest.configuration(directory);PkiAdminBootstrap.bootstrap(config,"administrator","approver","trusted-proxy");
        var clock=new TestClock();var keys=keys();
        try(var realm=ServerRealmContext.open(config.realm(),PkiSessionRuntimeDependencies.none())) {
            var control=AdministrativeWorkflowFixture.control(realm);
            try(var coordinator=coordinator(realm,control,clock)) {
                var request=request(realm);
                var ordinary=new AdministrativeRequest("ordinary",0,request.operation().name(),envelope(),new AdministrativeRequest.Actor("administrator",AdministrativeAuthenticationMode.DIRECT_MTLS,Optional.empty(),Optional.empty()),request.resource().scope(),"a".repeat(64),Optional.empty(),"b".repeat(64),AdministrativeRequest.State.READY,clock.instant(),clock.instant(),30000,Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty());
                var encoded=AdministrativeRequestCodec.encode(ordinary);
                assertFalse(new String(encoded.payload(),StandardCharsets.UTF_8).contains("sdkProof"));
                assertTrue(new String(encoded.payload(),StandardCharsets.UTF_8).contains("\"version\":1"));
                assertEquals(ordinary,AdministrativeRequestCodec.decode(encoded));
                String golden="{\"version\":1,\"requestId\":\"ordinary\",\"revision\":0,\"operation\":\"credential.issue\",\"envelope\":"+new String(zeroecho.pki.server.http.StrictJson.encode(envelope()),StandardCharsets.UTF_8)
                        +",\"scope\":{\"realmId\":\""+request.realmId().value()+"\",\"authorityId\":\"ca-fixture\",\"issuerId\":\"issuer-fixture\",\"profileId\":\"leaf-fixture\"},\"operationCommitment\":\""+"a".repeat(64)+"\",\"targetCommitment\":\""+"b".repeat(64)
                        +"\",\"state\":\"READY\",\"createdAt\":\"2026-11-14T12:00:00Z\",\"updatedAt\":\"2026-11-14T12:00:00Z\",\"executionTimeoutMillis\":30000,\"actor\":{\"principalId\":\"administrator\",\"mode\":\"DIRECT_MTLS\"}}";
                assertArrayEquals(golden.getBytes(StandardCharsets.UTF_8),encoded.payload());
                byte[] invalid=new String(encoded.payload(),StandardCharsets.UTF_8).replace("\"version\":1","\"version\":2").getBytes(StandardCharsets.UTF_8);
                assertThrows(IllegalArgumentException.class,()->AdministrativeRequestCodec.decode(new ServerControlStore.ProtocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,"ordinary",ApprovalService.digest(java.util.Base64.getEncoder().encodeToString(invalid)),invalid)));
                assertThrows(UnsupportedOperationException.class,()->realm.administrativeRequests().sdkAdmission().challenge(request,envelope(),keys.csr(),new byte[32]));
                assertTrue(control.protocolRecords(ServerControlStore.HYBRID_SDK_INTENT,0,10).values().isEmpty());
                var largeArguments=new java.util.LinkedHashMap<>(((PkiOperationValue.ObjectValue)envelope().fields().get("arguments")).fields());
                largeArguments.put("padding",new PkiOperationValue.ListValue(java.util.stream.IntStream.range(0,260).mapToObj(i->(PkiOperationValue)new PkiOperationValue.Text("x".repeat(1000))).toList()));
                var largeEnvelope=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),"arguments",new PkiOperationValue.ObjectValue(largeArguments)));
                var challenge=coordinator.sdkAdmission().challenge(request,largeEnvelope,keys.csr(),new byte[32]);
                byte[] first=sign(keys.primary(),"SHA384withECDSA",challenge.primary().encode());
                byte[] second=sign(keys.alternative(),"ML-DSA-87",new HybridSdkFrame(2,challenge.primary().fields()).encode());
                assertEquals("SDK_TOO_LARGE",assertThrows(IllegalArgumentException.class,()->coordinator.sdkAdmission().accept(challenge.intentId(),"oversized",request,largeEnvelope,Duration.ofSeconds(30),first,second)).getMessage());
                assertTrue(control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,"oversized").isEmpty());
                assertTrue(control.approvals(0,10).values().isEmpty());
                try(var tooLarge=new AdministrativeRequestCoordinator(realm,control,clock,()->{throw new AssertionError("never signs");},"https://example.invalid:443",(r,e,parsed)->{
                    var original=context(realm,r,e);var fields=original.target().fields();
                    fields.put(15,HybridSdkValue.object(Map.of("padding",HybridSdkValue.text("x".repeat(261000)))).encode());
                    return new HybridSdkAdmissionService.Context(original.admission(),new HybridSdkFrame(7,fields));
                })) {
                    assertEquals("SDK_TOO_LARGE",assertThrows(IllegalArgumentException.class,()->tooLarge.sdkAdmission().challenge(request,largeEnvelope,keys.csr(),new byte[32])).getMessage());
                }
                assertEquals(1,control.protocolRecords(ServerControlStore.HYBRID_SDK_INTENT,0,10).values().size());
            }
        }
    }

    private static AdministrativeRequestCoordinator conditionalCoordinator(ServerRealmContext realm,ServerControlStore control,Clock clock,
            java.util.concurrent.atomic.AtomicBoolean refuseFresh) {
        return new AdministrativeRequestCoordinator(realm,control,clock,()->{throw new UnsupportedOperationException("fixture never signs");},
                "https://example.invalid:443",(request,envelope,subject)->{
                    if (refuseFresh.get()) throw new SecurityException("Fixture current issuer/policy no longer admits new work");
                    var resolved=context(realm,request,envelope);var admitted=resolved.admission();
                    return new HybridSdkAdmissionService.Context(new ServerOperationGateway.Admission(admitted.request(),admitted.commitment(),admitted.policy(),
                            new AuthorizationEngine.Decision(AuthorizationEngine.Code.APPROVAL_REQUIRED,false)),resolved.target());
                });
    }
    private static AdministrativeRequestCoordinator coordinator(ServerRealmContext realm,ServerControlStore control,Clock clock) {
        return new AdministrativeRequestCoordinator(realm,control,clock,()->{throw new UnsupportedOperationException("fixture never signs");},
                "https://example.invalid:443",(request,envelope,subject)->context(realm,request,envelope));
    }
    private static HybridSdkAdmissionService.Context context(ServerRealmContext realm,ServerOperationGateway.Request request,PkiOperationValue.ObjectValue envelope) {
        var policy=realm.configuration().approvalPolicies().get(OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK);
        var admission=new ServerOperationGateway.Admission(request,"a".repeat(64),Optional.of(policy),new AuthorizationEngine.Decision(AuthorizationEngine.Code.ALLOWED,false));
        var binding=new HybridSdkFrame(8,Map.of(1,text("fixture:issuer.priv"),2,text(BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY.canonicalForm()),
                3,text(BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm()),4,HybridSdkFrame.primaryAlgorithm(),5,new byte[64]));
        var f=new TreeMap<Integer,byte[]>();f.put(1,text(request.operation().name()));f.put(2,HybridSdkAdmissionService.value(envelope.fields().get("arguments")).encode());
        f.put(3,text(request.principalId()));f.put(4,text("ca-fixture"));f.put(5,text("issuer-fixture"));f.put(6,text("path-fixture"));
        f.put(7,text("sha512:"+"0".repeat(128)));f.put(8,binding.encode());f.put(9,new byte[0]);f.put(10,text("leaf-fixture"));
        f.put(11,ByteBuffer.allocate(8).putLong(1).array());f.put(12,text("sha256:"+"1".repeat(64)));f.put(13,text("sha256:"+"2".repeat(64)));f.put(14,text("sha256:"+policy.commitment()));
        f.put(15,HybridSdkValue.object(Map.of()).encode());f.put(16,HybridSdkValue.object(Map.of()).encode());f.put(17,HybridSdkValue.object(Map.of()).encode());
        return new HybridSdkAdmissionService.Context(admission,new HybridSdkFrame(7,f));
    }
    private static ServerOperationGateway.Request request(ServerRealmContext realm) {
        var scope=new Permission.Scope(realm.configuration().realmId(),Optional.of(new PkiId("ca-fixture")),Optional.of(new PkiId("issuer-fixture")),Optional.of("leaf-fixture"));
        var resource=new Permission.Resource(Permission.ResourceType.AUTHORITY,scope,Optional.of(new PkiId("ca-fixture")),Optional.empty());
        return new ServerOperationGateway.Request(realm.configuration().realmId(),"administrator",AdministrativeAuthenticationMode.DIRECT_MTLS,Optional.empty(),
                Optional.of(new CertificateIdentityEvidence(realm.configuration().realmId(),"a".repeat(64),"b".repeat(64),Set.of("c".repeat(64)),"d".repeat(64))),
                new AdministrativeOperation.Signing(new PkiSigningOperation.IssueCredential(new PkiId("ca-fixture"),new PkiId("csr-fixture"),"leaf-fixture")),resource,Permission.Relationship.ANY,Permission.Context.empty(),Optional.empty(),"sdk-fixture");
    }
    private static ServerOperationGateway.Request withEvidence(ServerOperationGateway.Request request,CertificateIdentityEvidence evidence) {
        return new ServerOperationGateway.Request(request.realmId(),request.principalId(),request.authenticationMode(),request.transportPrincipalId(),Optional.of(evidence),request.operation(),request.resource(),request.relationship(),request.context(),request.approvalId(),request.correlationId());
    }
    private static AdministrativeRequest.Actor actor(ServerOperationGateway.Request request) {return new AdministrativeRequest.Actor(request.principalId(),request.authenticationMode(),request.transportPrincipalId(),request.credentialEvidence());}
    private static PkiOperationValue.ObjectValue envelope() {return AdministrativeWorkflowFixture.object("{\"version\":1,\"arguments\":{\"issuerCaId\":\"ca-fixture\",\"requestId\":\"csr-fixture\",\"profileId\":\"leaf-fixture\"}}");}
    private static Keys keys()throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();var ec=KeyPairGenerator.getInstance("EC");ec.initialize(new ECGenParameterSpec("secp384r1"));var primary=ec.generateKeyPair();
        var ml=KeyPairGenerator.getInstance("ML-DSA","BC");ml.initialize(MLDSAParameterSpec.ml_dsa_87);var alternative=ml.generateKeyPair();
        var extensions=new ExtensionsGenerator();extensions.addExtension(new ASN1ObjectIdentifier("2.5.29.72"),false,alternative.getPublic().getEncoded());
        byte[] csr=new JcaPKCS10CertificationRequestBuilder(new javax.security.auth.x500.X500Principal("CN=Alice Example"),primary.getPublic())
                .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,extensions.generate()).build(new JcaContentSignerBuilder("SHA384withECDSA").build(primary.getPrivate())).getEncoded();
        return new Keys(primary,alternative,csr);
    }
    private static byte[] sign(KeyPair keys,String algorithm,byte[] bytes)throws Exception {var signer=algorithm.equals("ML-DSA-87")?Signature.getInstance(algorithm,"BC"):Signature.getInstance(algorithm);if(algorithm.equals("ML-DSA-87"))signer.setParameter(new ContextParameterSpec(new byte[0]));signer.initSign(keys.getPrivate());signer.update(bytes);return signer.sign();}
    private static byte[] text(String value){return value.getBytes(StandardCharsets.UTF_8);}
    private static Object invoke(Object target,java.lang.reflect.Method method,Object[] arguments)throws Throwable {try{return method.invoke(target,arguments);}catch(InvocationTargetException failure){throw failure.getCause();}}
    private record Keys(KeyPair primary,KeyPair alternative,byte[] csr) { }
    private static final class TestClock extends Clock {
        private Instant now=Instant.parse("2026-11-14T12:00:00Z");
        void advance(long seconds){now=now.plusSeconds(seconds);}
        /**
         * {@inheritDoc}
         */
        @Override public ZoneId getZone(){return ZoneOffset.UTC;}
        /**
         * {@inheritDoc}
         */
        @Override public Clock withZone(ZoneId zone){return this;}
        /**
         * {@inheritDoc}
         */
        @Override public Instant instant(){return now;}
    }
}
