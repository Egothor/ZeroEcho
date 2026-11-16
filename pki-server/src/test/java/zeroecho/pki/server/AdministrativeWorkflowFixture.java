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
import java.nio.file.attribute.*;
import java.security.*;
import java.time.*;
import java.util.*;
import zeroecho.core.storage.*;
import zeroecho.core.io.*;
import zeroecho.pki.api.*;
import zeroecho.pki.api.profile.*;
import zeroecho.pki.application.*;
import zeroecho.pki.server.http.*;
/**
 * Builds durable administrative-workflow fixtures with explicit test-only capability seams.
 */
final class AdministrativeWorkflowFixture {
 /**
  * Public test-only password for the fixture signing keyring; never use it for deployed keys.
  */
 static final String PASSWORD="Workflow-fixture-123456";
 /**
  * Fails the standalone workflow fixture when an expected invariant is false.
  *
  * @param value invariant result
  * @param message assertion diagnostic
  * @throws AssertionError if value is false
  */
 static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
 /**
  * Creates the fixed version-one root-authority request envelope for a safe test subject.
  *
  * @param subject subject text already safe for insertion into the fixture JSON literal
  * @return typed root creation envelope using the root-ca profile and fixture private-key alias
  */
 static PkiOperationValue.ObjectValue envelope(String subject){return (PkiOperationValue.ObjectValue)StrictJson.parse(("{\"version\":1,\"arguments\":{\"formatId\":\"x509\",\"subjectRef\":\""+subject+"\",\"profileId\":\"root-ca\",\"keyRef\":\"fixture:root.prv\"}}").getBytes(),262144);}
 /**
  * Creates a trusted-proxy administrative root request with explicit test-only certificate evidence.
  *
  * @param c open fixture realm providing catalogue and realm identity
  * @param subject safe root subject text
  * @return authenticated typed root request carrying fixture authority and resource context
  */
 static ServerOperationGateway.Request request(ServerRealmContext c,String subject){var d=HttpOperationCodec.decode(PkiSigningOperation.CreateAuthority.NAME,StrictJson.encode(envelope(subject)),262144,c.configuration().realmId(),c.gateway()::descriptor);var r=c.configuration().realmId();return new ServerOperationGateway.Request(r,"bootstrap-admin",AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY,Optional.of("trusted-proxy"),Optional.of(new CertificateIdentityEvidence(r,"a".repeat(64),"d".repeat(64),Set.of("e".repeat(64)),"f".repeat(64))),d.operation(),d.resource(),Permission.Relationship.ANY,d.context(),Optional.empty(),"workflow");}
 /**
  * Executes the real durable administrative approval workflow, including restart and root publication.
  *
  * @param directory isolated filesystem root for control log, domain store, and signing keyring
  * @throws Exception if key setup, workflow processing, restart, or cleanup fails
  * @throws AssertionError if a workflow durability, approval, replay, or publication invariant differs
  */
 static void run(Path directory)throws Exception {
 AdministrativeRequestCoverage.verify();
 var config=configuration(directory,false);
 PkiAdminBootstrap.bootstrap(config,"bootstrap-admin","bootstrap-approver","trusted-proxy");
 config=configuration(directory,true);
 Path key=directory.resolve("keyring/signing.zek");Files.createDirectory(key.getParent(),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
 try(var password=new KeyringPassword(PASSWORD.toCharArray());var keys=KeyringStore.create(key,password)){var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);var pair=generator.generateKeyPair();keys.putPrivate("root.prv","RSA",pair.getPrivate());keys.putPublic("root.pub","RSA",pair.getPublic());}
 var deps=PkiSessionRuntimeDependencies.withKeyringUnlockProvider(()->new KeyringPassword(PASSWORD.toCharArray()));
 try(var c=ServerRealmContext.open(config.realm(),deps)){
 for(var p:BuiltInCertificateProfileCatalog.load(AdministrativeWorkflowFixture.class.getClassLoader()))if(p.definition().profileId().equals("root-ca")){c.session().profiles().importBuiltIn(p);c.session().profiles().activateProfile("root-ca",p.definition().profileVersion());}
 try{c.administrativeRequests().submit("invalid",request(c,"Bare Root"),envelope("Bare Root"),Duration.ofSeconds(30));throw new AssertionError("bad subject admitted");}catch(PkiException expected){check(expected.failureReason().orElse(null)==PkiFailureReason.CA_SUBJECT_INVALID,"wrong failure reason "+expected.failureReason());}
 try { c.approvals().requireCurrent("admin-request.invalid");throw new AssertionError("bad subject approval created"); } catch (IllegalArgumentException expected) {}
 var admitted=c.administrativeRequests().submit("once",request(c,"CN=Durable Root"),envelope("CN=Durable Root"),Duration.ofSeconds(30));check(admitted.state()==AdministrativeRequest.State.WAITING_APPROVAL,"not waiting");
 check(admitted.profileCommitment().isPresent(),"root profile was not pinned");
 var encoded=AdministrativeRequestCodec.encode(admitted);check(AdministrativeRequestCodec.decode(encoded).equals(admitted),"private record roundtrip changed intent");
 var framed=(PkiOperationValue.ObjectValue)StrictJson.parse(encoded.payload(),524288);
 var actor=(PkiOperationValue.ObjectValue)framed.fields().get("actor");var unknown=with(framed,"actor",with(actor,"unexpected",text("reject")));
 byte[] invalid=StrictJson.encode(unknown);
 try{AdministrativeRequestCodec.decode(new ServerControlStore.ProtocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,admitted.requestId(),ApprovalService.digest(Base64.getEncoder().encodeToString(invalid)),invalid));throw new AssertionError("unknown nested actor field accepted");}catch(IllegalArgumentException expected){}
 var existingControl=control(c);
 try{existingControl.mutateAdministrativeRequest(encoded,Optional.of("0".repeat(64)),Optional.empty(),Optional.empty());throw new AssertionError("stale request CAS accepted");}catch(IllegalStateException expected){}
 check(c.administrativeRequests().inspect("once","bootstrap-admin").equals(admitted),"stale CAS modified request");

 check(c.administrativeRequests().submit("once",request(c,"CN=Durable Root"),envelope("CN=Durable Root"),Duration.ofSeconds(30)).equals(admitted),"not idempotent");
 c.approvals().decide(admitted.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.APPROVE,"independent approval");
 // Exercise the actual acceptance boundary: its receipt and approval claim must already be durable.
 var crash=c.administrativeRequests().submit("accepted-crash",request(c,"CN=Accepted Crash Root"),envelope("CN=Accepted Crash Root"),Duration.ofSeconds(30));
 c.approvals().decide(crash.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.APPROVE,"independent crash approval");
 var control=control(c);var actual=c.session().semanticSigning().orElseThrow();
 var observed=(SemanticSigningService)java.lang.reflect.Proxy.newProxyInstance(SemanticSigningService.class.getClassLoader(),new Class<?>[]{SemanticSigningService.class},(proxy,method,arguments)->{
   if(method.getName().equals("accept")){
     var retained=AdministrativeRequestCodec.decode(control.protocolRecord(ServerControlStore.ADMINISTRATIVE_REQUEST,"accepted-crash").orElseThrow());
     check(retained.state()==AdministrativeRequest.State.DISPATCHING&&retained.receipt().isPresent(),"accept preceded durable receipt");
     check(c.approvals().requireCurrent(crash.approvalId().orElseThrow()).state()==ApprovalService.State.EXECUTING,"accept preceded approval claim");
   }
   if(method.getName().equals("resolve"))throw new PkiException("fixture observation unavailable",PkiFailureReason.STORE_DURABILITY_UNCONFIRMED);
   try{return method.invoke(actual,arguments);}catch(java.lang.reflect.InvocationTargetException failed){throw failed.getCause();}
 });
 try(var crashing=new AdministrativeRequestCoordinator(c,control,Clock.systemUTC(),()->observed)){
   var retained=crashing.process("accepted-crash");
   check(retained.state()==AdministrativeRequest.State.DISPATCHING&&retained.receipt().isPresent(),"uncertain accepted signing falsely terminal");
   check(retained.failureCode().orElseThrow().equals("SIGNING_OBSERVATION_UNAVAILABLE"),"missing uncertainty diagnostic");
   long completedBy=System.nanoTime()+Duration.ofSeconds(15).toNanos();
   while(actual.find(retained.receipt().orElseThrow().operationId()).orElseThrow().state()!=zeroecho.pki.api.signing.SemanticSigningState.COMPLETED){
     if(System.nanoTime()>completedBy)throw new AssertionError("real signing failed to finish before simulated projection restart");Thread.sleep(20);
   }
 }

 var beforeAccept=c.administrativeRequests().submit("before-accept",request(c,"CN=Before Acceptance Root"),envelope("CN=Before Acceptance Root"),Duration.ofSeconds(30));
 c.approvals().decide(beforeAccept.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.APPROVE,"explicit approval before acceptance");
 var notAccepted=(SemanticSigningService)java.lang.reflect.Proxy.newProxyInstance(SemanticSigningService.class.getClassLoader(),new Class<?>[]{SemanticSigningService.class},(proxy,method,arguments)->{
   if(method.getName().equals("accept"))throw new IllegalStateException("simulated interruption before provider acceptance");
   try{return method.invoke(actual,arguments);}catch(java.lang.reflect.InvocationTargetException failed){throw failed.getCause();}
 });
 try(var interrupted=new AdministrativeRequestCoordinator(c,control,Clock.systemUTC(),()->notAccepted)){
   var reset=interrupted.process("before-accept");check(reset.state()==AdministrativeRequest.State.READY&&reset.receipt().isEmpty(),"proven nonacceptance did not reset safely");
   check(c.approvals().requireCurrent(beforeAccept.approvalId().orElseThrow()).state()==ApprovalService.State.APPROVED,"nonacceptance lost human decision");
 }
 var refused=c.administrativeRequests().submit("refused",request(c,"CN=Refused Root"),envelope("CN=Refused Root"),Duration.ofSeconds(30));
 c.approvals().decide(refused.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.REJECT,"explicit refusal");
 check(c.administrativeRequests().process("refused").state()==AdministrativeRequest.State.REJECTED,"rejection dispatched");
 var expired=c.administrativeRequests().submit("expired",request(c,"CN=Expired Approval Root"),envelope("CN=Expired Approval Root"),Duration.ofSeconds(30));
 var pending=c.approvals().requireCurrent(expired.approvalId().orElseThrow());
 control.replaceApproval(pending,new ApprovalService.Request(pending.approvalId(),pending.operationId(),pending.operationCommitment(),pending.scope(),pending.requesterPrincipalId(),pending.createdAt(),pending.expiresAt(),pending.policy(),pending.policyCommitment(),ApprovalService.State.EXPIRED,pending.decisions(),pending.resultClassification()));
 check(c.administrativeRequests().process("expired").state()==AdministrativeRequest.State.EXPIRED,"expired approval dispatched");

 try{c.administrativeRequests().submit("once",request(c,"CN=Different Root"),envelope("CN=Different Root"),Duration.ofSeconds(30));throw new AssertionError("conflicting target accepted");}catch(AdministrativeRequestCoordinator.Conflict expected){}
 var disabled=c.administrativeRequests().submit("disabled",request(c,"CN=Disabled Requester Root"),envelope("CN=Disabled Requester Root"),Duration.ofSeconds(30));
 c.approvals().decide(disabled.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.APPROVE,"approve before disable");
 c.setPrincipalEnabled("bootstrap-admin",false,"bootstrap-approver");
 var denied=c.administrativeRequests().process("disabled");check(denied.state()==AdministrativeRequest.State.FAILED&&denied.receipt().isEmpty(),"disabled requester dispatched");
 c.setPrincipalEnabled("bootstrap-admin",true,"bootstrap-approver");
 var unmapped=c.administrativeRequests().submit("unmapped",request(c,"CN=Removed Mapping Root"),envelope("CN=Removed Mapping Root"),Duration.ofSeconds(30));
 c.approvals().decide(unmapped.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.APPROVE,"approve before mapping removal");
 var auth=config.authentication();
 var changedAuth=new PkiServerConfiguration.Authentication(auth.mode(),auth.directClientMappings(),auth.proxyTransportMappings(),auth.forwardedClientMappings().stream().filter(mapping -> !mapping.principalId().equals("bootstrap-admin")).toList(),auth.trustedProxyPrincipalIds(),auth.forwardedCertificateFormat(),auth.forwardedCertificateHeaderName(),auth.forwardedCertificateChainHeaderName(),auth.administrativeClientTrust(),auth.maximumForwardedCertificateBytes(),auth.maximumForwardedChainBytes());
 try(var mapped=new AdministrativeRequestCoordinator(c,control,Clock.systemUTC())) {
   var field=AdministrativeRequestCoordinator.class.getDeclaredField("authentication");field.setAccessible(true);field.set(mapped,changedAuth);
   var stopped=mapped.process("unmapped");check(stopped.state()==AdministrativeRequest.State.FAILED&&stopped.receipt().isEmpty(),"removed mapping dispatched");
 }

 var changed=c.administrativeRequests().submit("profile-changed",request(c,"CN=Changed Profile Root"),envelope("CN=Changed Profile Root"),Duration.ofSeconds(30));
 c.approvals().decide(changed.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.APPROVE,"approve frozen profile");
 var active=c.session().profiles().requireActiveProfile("root-ca").reference();
 var imported=c.session().profiles().getImportedVersion("root-ca",active.profileVersion()).orElseThrow();
 var document=(PkiOperationValue.ObjectValue)StrictJson.parse(imported.canonicalJson(),1048576);
 var next=with(document,"profileVersion",new PkiOperationValue.IntegerValue(active.profileVersion()+1));
 c.session().profiles().importProfile(StrictJson.encode(next));c.session().profiles().activateProfile("root-ca",active.profileVersion()+1);
 var stale=c.administrativeRequests().process("profile-changed");check(stale.state()==AdministrativeRequest.State.FAILED&&stale.failureCode().orElseThrow().equals("PROFILE_CHANGED")&&stale.receipt().isEmpty(),"changed profile signed: "+stale.state()+stale.failureCode()+stale.receipt());
 c.session().profiles().activateProfile("root-ca",active.profileVersion());
 var copy=with(document,"profileId",text("root-copy"));
 var genericEnvelope=new PkiOperationValue.ObjectValue(Map.of("version",new PkiOperationValue.IntegerValue(1),"arguments",new PkiOperationValue.ObjectValue(Map.of("document",text(Base64.getEncoder().encodeToString(StrictJson.encode(copy)))))));
 var grantEnvelope=object("{\"version\":1,\"arguments\":{\"grantId\":\"queued.realm-read\",\"principalId\":\"bootstrap-approver\",\"effect\":\"ALLOW\",\"action\":\"REALM_READ\",\"resourceType\":\"REALM\",\"relationship\":\"ANY\",\"dataView\":\"METADATA_REDACTED\",\"conditions\":[]}}");
 var grantRequest=genericRequest(c,ServerControlOperation.CreateGrant.NAME,grantEnvelope);
 var governance=c.administrativeRequests().submit("governance",grantRequest,grantEnvelope,Duration.ofSeconds(30));
 check(governance.state()==AdministrativeRequest.State.WAITING_APPROVAL,"governance mutation lacks automatic approval");
 c.approvals().decide(governance.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.APPROVE,"independent exact grant approval");
 check(c.administrativeRequests().process("governance").state()==AdministrativeRequest.State.SUCCEEDED,"approved grant not continued");
 check(control.requireGrant("queued.realm-read").principalId().equals("bootstrap-approver"),"queued grant not persisted");
 try{c.administrativeRequests().submit("governance-duplicate",grantRequest,grantEnvelope,Duration.ofSeconds(30));throw new AssertionError("known duplicate grant queued for approval");}catch(AdministrativeRequestCoordinator.ValidationFailure expected){}
 try{c.approvals().requireCurrent("admin-request.governance-duplicate");throw new AssertionError("duplicate grant obtained approval");}catch(IllegalArgumentException expected){}
 var enrollmentEnvelope=object("{\"version\":1,\"arguments\":{\"id\":\"managed-enrollment\",\"displayName\":\"Managed enrollment\",\"certificateProfileId\":\"server-tls\",\"requireApproval\":true}}");
 var enrollmentRequest=genericRequest(c,ServerControlOperation.RegisterEnrollmentProfile.NAME,enrollmentEnvelope);
 var enrollment=c.administrativeRequests().submit("enrollment",enrollmentRequest,enrollmentEnvelope,Duration.ofSeconds(30));
 check(c.enrollmentProfiles().find("managed-enrollment").isEmpty(),"preflight persisted enrollment policy before approval");
 c.approvals().decide(enrollment.approvalId().orElseThrow(),"bootstrap-approver",ApprovalService.Choice.APPROVE,"approve retained enrollment policy");
 check(c.administrativeRequests().process("enrollment").state()==AdministrativeRequest.State.SUCCEEDED,"enrollment policy did not continue");
 var enrollmentPolicy=c.enrollmentProfiles().find("managed-enrollment").orElseThrow();
 c.enrollmentProfiles().validateUpdate(enrollmentPolicy.withState(zeroecho.pki.server.enrollment.EnrollmentProfileState.SUSPENDED));
 check(c.enrollmentProfiles().find("managed-enrollment").orElseThrow().equals(enrollmentPolicy),"pure update changed enrollment policy");
 try{c.administrativeRequests().submit("enrollment-duplicate",enrollmentRequest,enrollmentEnvelope,Duration.ofSeconds(30));throw new AssertionError("duplicate enrollment queued");}catch(AdministrativeRequestCoordinator.ValidationFailure expected){}
 var genericRequest=genericRequest(c,PkiOperation.RegisterProfile.NAME,genericEnvelope);
 c.createPrincipal(new SecurityPrincipal("conditional",SecurityPrincipal.Type.USER,"Synthetic conditional requester",Optional.empty(),Map.of(),true),"bootstrap-admin");
 var conditionScope=new Permission.Scope(c.configuration().realmId(),Optional.empty(),Optional.empty(),Optional.empty());
 c.grant(new Permission.Grant("conditional.profile-register","conditional",Permission.Effect.ALLOW,Permission.Action.PROFILE_REGISTER,Permission.ResourceType.PROFILE,conditionScope,Permission.Relationship.ANY,Permission.DataView.METADATA_REDACTED,Set.of(Permission.Condition.APPROVAL_REQUIRED),Optional.empty(),true),"bootstrap-admin");
 var conditional=new ServerOperationGateway.Request(genericRequest.realmId(),"conditional",genericRequest.authenticationMode(),genericRequest.transportPrincipalId(),Optional.empty(),genericRequest.operation(),genericRequest.resource(),genericRequest.relationship(),genericRequest.context(),Optional.empty(),"conditional");
 try{c.administrativeRequests().submit("unsupported-category",conditional,genericEnvelope,Duration.ofSeconds(30));throw new AssertionError("arbitrary NONE approval grant created a policy");}catch(SecurityException expected){}
 try{c.approvals().requireCurrent("admin-request.unsupported-category");throw new AssertionError("unsupported category approval persisted");}catch(IllegalArgumentException expected){}

 var generic=c.administrativeRequests().submit("approval-free",genericRequest,genericEnvelope,Duration.ofSeconds(30));
 check(generic.approvalId().isEmpty()&&generic.state()==AdministrativeRequest.State.READY,"NONE operation created approval");
 check(c.administrativeRequests().process("approval-free").state()==AdministrativeRequest.State.SUCCEEDED,"approval-free mutation failed");
 var uncertain=c.administrativeRequests().submit("generic-crash",genericRequest,genericEnvelope,Duration.ofSeconds(30));
 var dispatching=new AdministrativeRequest(uncertain.requestId(),1,uncertain.operation(),uncertain.envelope(),uncertain.actor(),uncertain.scope(),uncertain.operationCommitment(),uncertain.profileCommitment(),uncertain.targetCommitment(),AdministrativeRequest.State.DISPATCHING,uncertain.createdAt(),uncertain.updatedAt(),uncertain.executionTimeoutMillis(),Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty(),Optional.empty());
 control.mutateAdministrativeRequest(AdministrativeRequestCodec.encode(dispatching),Optional.of(AdministrativeRequestCodec.encode(uncertain).commitment()),Optional.empty(),Optional.empty());
 check(c.administrativeRequests().process("generic-crash").state()==AdministrativeRequest.State.RECONCILIATION_REQUIRED,"uncertain generic mutation replayed");



 }
 try(var c=ServerRealmContext.open(config.realm(),deps)){
 c.administrativeRequests().start(config.authentication());
 long end=System.nanoTime()+Duration.ofSeconds(30).toNanos();AdministrativeRequest result;
 do{Thread.sleep(100);result=c.administrativeRequests().inspect("once","bootstrap-admin");if(result.terminal())break;}while(System.nanoTime()<end);
 check(result.state()==AdministrativeRequest.State.SUCCEEDED,"workflow did not succeed: "+result.state()+" "+result.failureCode());
 check(result.receipt().isPresent()&&result.result().isPresent(),"final receipt/result missing");
 do{Thread.sleep(100);result=c.administrativeRequests().inspect("accepted-crash","bootstrap-admin");if(result.terminal())break;}while(System.nanoTime()<end);
 check(result.state()==AdministrativeRequest.State.SUCCEEDED,"accepted receipt recovery failed: "+result.state()+result.failureCode());
 do{Thread.sleep(100);result=c.administrativeRequests().inspect("before-accept","bootstrap-admin");if(result.terminal())break;}while(System.nanoTime()<end);
 check(result.state()==AdministrativeRequest.State.SUCCEEDED,"proven nonacceptance restart failed: "+result.state()+result.failureCode());
 var caList=(PkiOperationOutcome.Completed)c.session().operations().execute(new PkiOperation.ListAuthorities(100),CancellationSignal.NONE);
 var authorities=(PkiOperationValue.ListValue)caList.result().fields().get("authorities");
 check(authorities.values().size()==3,"unexpected actual CA count (duplicate or failed continuation): "+authorities.values().size());
System.out.println("PASS submit once; bad DN rejected before approval; idempotent; independent approval; restart worker produces real CA: "+result.result().get());
 }
 }
 /**
  * Binds a typed operation envelope to the fixture's trusted-proxy requester identity.
  *
  * @param context open fixture realm
  * @param operation semantic operation name resolved by the gateway catalogue
  * @param envelope typed version-one operation envelope
  * @return authenticated request retaining decoded scope and explicit fixture evidence
  */
 static ServerOperationGateway.Request genericRequest(ServerRealmContext context,String operation,PkiOperationValue.ObjectValue envelope){
 var decoded=HttpOperationCodec.decode(operation,StrictJson.encode(envelope),262144,context.configuration().realmId(),context.gateway()::descriptor);
 var original=request(context,"CN=unused");return new ServerOperationGateway.Request(original.realmId(),original.principalId(),original.authenticationMode(),original.transportPrincipalId(),original.credentialEvidence(),decoded.operation(),decoded.resource(),Permission.Relationship.ANY,decoded.context(),Optional.empty(),"generic");
 }
 /**
  * Opens only a test collaborator seam; no production API exposes the private control authority.
  * @param context open fixture realm whose private control collaborator is inspected
  * @return borrowed private control store; the realm remains its lifecycle owner
  * @throws Exception if reflective fixture access is unavailable
  */
 static ServerControlStore control(ServerRealmContext context)throws Exception{var field=ServerRealmContext.class.getDeclaredField("control");field.setAccessible(true);return (ServerControlStore)field.get(context);}
 /**
  * Parses one bounded UTF-8 fixture JSON object without accepting a different root type.
  *
  * @param json valid object JSON bounded to one MiB after encoding
  * @return typed immutable JSON object
  * @throws IllegalArgumentException if JSON is malformed or exceeds the parser bound
  * @throws ClassCastException if the root value is not an object
  */
 static PkiOperationValue.ObjectValue object(String json) {return (PkiOperationValue.ObjectValue)StrictJson.parse(json.getBytes(java.nio.charset.StandardCharsets.UTF_8),1048576);}
 /**
  * Copies a typed object and replaces or adds one field without modifying the original.
  *
  * @param original source typed object
  * @param key field name to replace or add
  * @param value new field value
  * @return new typed object containing the replaced field
  */
 static PkiOperationValue.ObjectValue with(PkiOperationValue.ObjectValue original,String key,PkiOperationValue value){var fields=new LinkedHashMap<>(original.fields());fields.put(key,value);return new PkiOperationValue.ObjectValue(fields);}
 /**
  * Wraps fixture text as a typed operation argument.
  *
  * @param value text value; must not be null
  * @return typed immutable text value
  * @throws NullPointerException if value is null
  */
 static PkiOperationValue.Text text(String value){return new PkiOperationValue.Text(value);}
 /**
  * Derives a fixture realm from the committed trusted-proxy example with isolated filesystem paths.
  *
  * @param directory fixture root for control, keyring, store, and backup artifacts
  * @param signing whether to include the real local signing provider configuration
  * @return decoded server configuration with disabled public listener and explicit approval policy
  * @throws Exception if the committed example cannot be located, read, or decoded
  */
 static PkiServerConfiguration configuration(Path directory,boolean signing)throws Exception {
 Path repository=Path.of("").toAbsolutePath();if(!Files.isDirectory(repository.resolve("docs")))repository=repository.getParent();
 var document=(PkiOperationValue.ObjectValue)StrictJson.parse(Files.readAllBytes(repository.resolve("documentation/examples/configuration/pki-server-trusted-proxy-rfc9440-example.json")),1048576);
 var realm=(PkiOperationValue.ObjectValue)document.fields().get("realm");
 var session=(PkiOperationValue.ObjectValue)realm.fields().get("pkiSession");
 session=with(session,"store",with(object("{\"id\":\"fs\",\"properties\":{}}"),"properties",new PkiOperationValue.ObjectValue(Map.of("root",text(directory.resolve("store").toString())))));
 session=with(session,"audit",object("{\"id\":\"memory\",\"properties\":{\"size\":\"1024\"}}"));
 if(signing){var setup=object("{\"provider\":{\"id\":\"zeroecho-lib\",\"properties\":{}},\"signatureAlgorithm\":\"zealg:2:9:signature8:zeroecho14:rsa-pkcs1-v1_516:zeroecho.builtin39:ZGlnZXN0PXplcm9lY2hvLnNoYTItMjU2Lm5vbmU\",\"signingTtlMillis\":120000,\"topology\":{\"coordinator\":{\"pageSize\":1,\"claimLeaseMillis\":5000,\"providerCallTimeoutMillis\":1000,\"idlePollIntervalMillis\":20,\"closeTimeoutMillis\":5000},\"exactGroups\":[],\"catchAll\":{\"laneCount\":1,\"prefetchSize\":1}}}");
 setup=with(setup,"provider",new PkiOperationValue.ObjectValue(Map.of("id",text("zeroecho-lib"),"properties",new PkiOperationValue.ObjectValue(Map.of("keyringPath",text(directory.resolve("keyring/signing.zek").toString()),"keyRefPrefix",text("fixture:"),"requireComponentSuffix",text("true"))))));session=with(session,"signing",setup);}
 realm=with(realm,"pkiSession",session);realm=with(realm,"controlLog",text(directory.resolve("control.log").toString()));
 realm=with(realm,"authorityExposure",object("{\"mode\":\"ALL_REALM_AUTHORITIES\",\"authorityIds\":[],\"creationPermitted\":true}"));
 realm=with(realm,"approvalPolicy",object("{\"policyId\":\"high-risk\",\"threshold\":1,\"eligibleApprovers\":[\"bootstrap-admin\",\"bootstrap-approver\"],\"requiredRoleTemplateIds\":[],\"requesterSeparation\":true,\"lifetimeMillis\":3600000,\"justificationRequired\":true}"));
 realm=with(realm,"approvalCommitment",text(ApprovalService.digest("high-risk|1|bootstrap-admin,bootstrap-approver||true|3600|true")));
 document=with(document,"realm",realm);
 var auth=(PkiOperationValue.ObjectValue)document.fields().get("authentication");
 auth=with(auth,"proxyTransportMappings",new PkiOperationValue.ListValue(List.of(mapping("proxy","trusted-proxy","c"))));
 auth=with(auth,"forwardedClientMappings",new PkiOperationValue.ListValue(List.of(mapping("admin","bootstrap-admin","a"),mapping("approver","bootstrap-approver","b"))));
 document=with(document,"authentication",auth);document=with(document,"publicListener",object("{\"enabled\":false}"));
 return PkiServerConfigurationCodec.decode(StrictJson.encode(document));
 }
 /**
  * Builds one deterministic certificate-to-principal mapping JSON value.
  *
  * @param id mapping identity
  * @param principal principal identity to bind
  * @param digest single hexadecimal character repeated 64 times for the test fingerprint
  * @return typed mapping object containing the exact fixture certificate fingerprint
  */
 static PkiOperationValue.ObjectValue mapping(String id,String principal,String digest){return new PkiOperationValue.ObjectValue(Map.of("mappingId",text(id),"principalId",text(principal),"certificateSha256",text(digest.repeat(64))));}
 /**
  * Runs the repository fixture directly when external JUnit dependencies cannot be downloaded.
  * @param args unused standalone fixture arguments
  * @throws Exception if temporary root creation or workflow execution fails
  */
 public static void main(String[] args)throws Exception{run(Files.createTempDirectory("zeroecho-workflow-domain-"));}

}
