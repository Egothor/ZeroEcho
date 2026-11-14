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

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.StrictJson;

/**
 * Test-only stopped-fixture provisioning of protocol custody under an already created CA.
 * No existing installation path is inferred, no private key is exported, and no
 * enrollment decision/account/transaction is fabricated. Run only in the nonce-owned
 * disposable container after its launcher proves that its exact backend is stopped.
 */
public final class ExerciseProtocolSeed {
    private ExerciseProtocolSeed() { }
    /**
     * Provisions encrypted protocol custody and a strict runtime companion.
     * @param arguments fresh fixture root, nonce, run ID, logical CA ID and exact CA credential ID;
     *        optional --client-password-stdin prefix reads a separate client-custody secret from stdin
     * @throws Exception if any ownership, stopped proof, CA/key binding or storage invariant fails
     */
    public static void main(String[] arguments) throws Exception {
        boolean clientInput=arguments.length==6&&arguments[0].equals("--client-password-stdin");
        char[] clientPassword=null;
        if(clientInput) {
            String line=new java.io.BufferedReader(new java.io.InputStreamReader(System.in,java.nio.charset.StandardCharsets.UTF_8)).readLine();
            if(line==null||line.isEmpty()||line.length()>1024)throw new IllegalArgumentException("Independent client unlock input required");
            clientPassword=line.toCharArray();arguments=java.util.Arrays.copyOfRange(arguments,1,arguments.length);
        }
        boolean wire=arguments.length==6&&arguments[0].equals("--cmp-wire");
        if(arguments.length!=5&&!wire)throw new IllegalArgumentException("Five seed arguments or --cmp-wire root nonce runId origin label required");
        String secret=System.getenv("ZEROECHO_KEYRING_PASSWORD");
        if(secret==null||secret.isEmpty())throw new IllegalArgumentException("Fixture keyring unlock capability required");
        char[] password=secret.toCharArray();
        try {
            if(wire)cmpWire(Path.of(arguments[1]),arguments[2],arguments[3],java.net.URI.create(arguments[4]),arguments[5],password);
            else seed(Path.of(arguments[0]),arguments[1],arguments[2],arguments[3],arguments[4],password,clientPassword==null?password:clientPassword);
        }
        finally {java.util.Arrays.fill(password,'\0');if(clientPassword!=null)java.util.Arrays.fill(clientPassword,'\0');}
        System.out.println(wire?"CMP_GENERAL_MESSAGE_VERIFIED":"PROTOCOL_FIXTURE_READY");
    }
    static void seed(Path root,String nonce,String runId,String authorityId,String credentialId,char[] password)throws Exception {
        seed(root,nonce,runId,authorityId,credentialId,password,password);
    }
    static void seed(Path root,String nonce,String runId,String authorityId,String credentialId,char[] password,char[] clientPassword)throws Exception {
        root=root.toAbsolutePath().normalize();privatePath(root,true);
        if(!nonce.matches("[0-9a-f]{32}")||!runId.matches("[0-9a-f]{32}"))throw new IllegalArgumentException("Invalid fixture nonce");
        if(!text(object(root.resolve(".exercise-owner.json")),"nonce").equals(nonce))throw new IllegalStateException("Fixture owner differs");
        Path configurationPath=root.resolve("config/server.json");privatePath(configurationPath,false);
        var configuration=PkiServerConfigurationCodec.read(configurationPath);
        if(!configuration.realm().realmId().value().equals("zeroecho-exercise-"+nonce))throw new IllegalStateException("Fixture realm differs");
        Path store=Path.of(configuration.realm().pkiSessionConfiguration().store().require("root"));
        if(!Files.isRegularFile(store.resolve("VERSION"),LinkOption.NOFOLLOW_LINKS)||!Files.isSameFile(store,root.resolve("store-container/store")))throw new IllegalStateException("Initialized owned store required");
        Path authorization=root.resolve(".exercise-protocol-authorization.json");var proof=object(authorization);
        if(!proof.keySet().equals(Set.of("nonce","runId","authorityId","credentialId","backendStopped","serverId","ticket"))
                ||!text(proof,"nonce").equals(nonce)||!text(proof,"runId").equals(runId)||!text(proof,"authorityId").equals(authorityId)||!text(proof,"credentialId").equals(credentialId)
                ||!(proof.get("backendStopped") instanceof PkiOperationValue.BooleanValue stopped)||!stopped.value()
                ||!text(proof,"serverId").matches("[0-9a-f]{64}")||!text(proof,"ticket").matches("[0-9a-f]{32}"))throw new IllegalStateException("Stopped fixture proof differs");
        Path custody=root.resolve("keyring/protocol-custody");
        if(Files.exists(custody,LinkOption.NOFOLLOW_LINKS))throw new IllegalStateException("Protocol custody already exists; inspect the interrupted fixture");
        var dependencies=PkiSessionRuntimeDependencies.withKeyringUnlockProvider(()->new KeyringPassword(password.clone()));
        var r=configuration.realm();var session=r.pkiSessionConfiguration();
        var readSession=new zeroecho.pki.application.PkiSessionConfiguration(session.version(),session.store(),session.audit(),Optional.empty(),session.publishers(),session.bindingProviders());
        var readRealm=new ServerRealmConfiguration(r.realmId(),r.displayName(),r.confirmationProofPolicy(),readSession,r.authorityExposure(),r.authorizationCommitment(),r.approvalCommitment(),r.extendedApprovalCommitment(),r.disclosureCommitment(),r.disclosureDefaults(),r.controlLogPath(),r.controlStoreId(),r.approvalPolicies());
        try(var context=ServerRealmContext.open(readRealm,dependencies)) {
            var repository=context.session().repository();var ca=repository.authority(new PkiId(authorityId)).orElseThrow();
            var issuer=repository.issuer(ca.currentIssuanceIssuerId()).orElseThrow();
            if(!issuer.credentialId().value().equals(credentialId))throw new IllegalStateException("Exact current CA credential differs");
            java.security.cert.X509Certificate authority;
            try(var lease=repository.openCredential(issuer.credentialId());var input=lease.openStream()) {
                authority=(java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);
            }
            if(!authority.getSubjectX500Principal().getName().contains(runId)||authority.getBasicConstraints()<0)throw new IllegalStateException("CA is not owned by this exercise run");
            var signing=configuration.realm().pkiSessionConfiguration().signing().orElseThrow();
            Path signingRing=Path.of(signing.provider().require("keyringPath"));
            if(!Files.isSameFile(signingRing,root.resolve("keyring/ca-keyring.zek")))throw new IllegalStateException("CA custody escaped fixture");
            Files.move(authorization,root.resolve(".exercise-protocol-consumed-"+text(proof,"ticket")+".json"),StandardCopyOption.ATOMIC_MOVE);
            Files.createDirectory(custody,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            Path runtimeRoot=signingRing.getParent().getParent();
            Path rootCertificate=custody.resolve("authority.der");write(rootCertificate,authority.getEncoded());
            Path protocolRing=custody.resolve("custody.zek");
            var sets=new java.util.ArrayList<PkiOperationValue>();var active=new java.util.ArrayList<PkiOperationValue>();
            try(var unlock=new KeyringPassword(password.clone());var rootRing=KeyringStore.open(signingRing,unlock);var protocolUnlock=new KeyringPassword(password.clone());var ring=KeyringStore.create(protocolRing,protocolUnlock)) {
                var key=rootRing.getPrivate("root.prv");
                var proofSignature=java.security.Signature.getInstance("SHA256withRSA");proofSignature.initSign(key);proofSignature.update(runId.getBytes(java.nio.charset.StandardCharsets.US_ASCII));var signature=proofSignature.sign();
                proofSignature.initVerify(authority.getPublicKey());proofSignature.update(runId.getBytes(java.nio.charset.StandardCharsets.US_ASCII));if(!proofSignature.verify(signature))throw new IllegalStateException("Protected root key does not match the frozen CA");
                var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(3072);
                int sequence=1;
                for(String protocol:List.of("EST","SCEP","CMP")) {
                    var pair=generator.generateKeyPair();String alias=protocol.toLowerCase(java.util.Locale.ROOT)+"-ra";
                    var ra=zeroecho.pkix.Pkix.certificateBuilder().subject(new javax.security.auth.x500.X500Principal("CN=Disposable "+alias+" "+runId)).issuer(authority.getSubjectX500Principal()).publicKey(pair.getPublic()).serialNumber(java.math.BigInteger.valueOf(100000L+sequence++))
                            .validity(Clock.systemUTC().instant().minusSeconds(30),Clock.systemUTC().instant().plus(Duration.ofHours(4)))
                            .basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(),true).keyUsage(Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE,zeroecho.pkix.KeyUsage.KEY_ENCIPHERMENT),true)
                            .build(zeroecho.pkix.Pkix.signer(key,zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
                    ra.verify(authority.getPublicKey());ring.putPrivate(alias,"RSA",pair.getPrivate());write(custody.resolve(alias+".der"),ra.getEncoded());
                    String identity="exercise-"+runId+"-"+alias;
                    var signer=object(Map.of("key",object(Map.of("keyringId",text("protocol-custody"),"alias",text(alias))),"certificateChain",list(List.of(text(runtimeRoot.resolve("keyring/protocol-custody/"+alias+".der").toString()),text(runtimeRoot.resolve("keyring/protocol-custody/authority.der").toString())))));
                    var fields=new java.util.LinkedHashMap<String,PkiOperationValue>();fields.put("credentialId",text(identity));fields.put("protocol",text(protocol));fields.put("authorityId",text(authorityId));fields.put("issuerId",text(issuer.issuerId().value()));fields.put("chainPathId",text(ca.issuanceChainPathId().value()));fields.put("signer",signer);
                    fields.put("requestTrustAnchors",list(protocol.equals("CMP")?List.of(text(runtimeRoot.resolve("keyring/protocol-custody/authority.der").toString())):List.of()));fields.put("authorizedRaKeys",list(List.of()));sets.add(object(fields));
                    active.add(object(Map.of("protocol",text(protocol),"authorityId",text(authorityId),"credentialId",text(identity))));
                }
                var client=generator.generateKeyPair();
                var clientCertificate=zeroecho.pkix.Pkix.certificateBuilder().subject(new javax.security.auth.x500.X500Principal("CN=Disposable CMP client "+runId)).issuer(authority.getSubjectX500Principal()).publicKey(client.getPublic()).serialNumber(java.math.BigInteger.valueOf(200001))
                        .validity(Clock.systemUTC().instant().minusSeconds(30),Clock.systemUTC().instant().plus(Duration.ofHours(4)))
                        .basicConstraints(zeroecho.pkix.BasicConstraints.endEntity(),true).keyUsage(Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE),true)
                        .build(zeroecho.pkix.Pkix.signer(key,zeroecho.pkix.AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
                write(custody.resolve("cmp-client.der"),clientCertificate.getEncoded());
                Files.createDirectory(root.resolve("protocol-client"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                storeClientKeyring(root.resolve("protocol-client/client.zek"),clientPassword,client.getPrivate());
            }
            var budgets=object(Map.of("maximumTransactions",integer(100),"maximumPending",integer(32),"maximumRetainedRequestBytes",integer(16777216),"maximumRequestBytes",integer(1048576),"maximumConcurrentDispatches",integer(2),"pendingLifetimeSeconds",integer(3600),"retryAfterSeconds",integer(1)));
            var companion=object(Map.of("version",integer(1),"budgets",budgets,"keyrings",list(List.of(object(Map.of("id",text("protocol-custody"),"path",text(runtimeRoot.resolve("keyring/protocol-custody/custody.zek").toString()))))),"credentialSets",list(sets),"activeCredentials",list(active)));
            Path companionPath=root.resolve("config/enrollment-runtime.json");privatePath(companionPath,false);
            var previous=object(companionPath);
            if(!(previous.get("credentialSets") instanceof PkiOperationValue.ListValue empty)||!empty.values().isEmpty())throw new IllegalStateException("Initial empty protocol companion required");
            Path candidate=root.resolve("config/enrollment-runtime.prepared.json");write(candidate,StrictJson.encode(companion));
            Files.move(candidate,companionPath,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);
            String policy="exercise-"+runId+"-protocol-policy";
            context.enrollmentProfiles().register(new zeroecho.pki.server.enrollment.EnrollmentProfile(policy,"Disposable protocol prerequisites",zeroecho.pki.server.enrollment.EnrollmentProfileState.ACTIVE,"server-tls",Set.of(authorityId),Optional.empty(),List.of(),true));
            write(root.resolve("config/protocol-context.json"),StrictJson.encode(object(Map.of("protocolAuthorityId",text(authorityId),"protocolIssuerId",text(issuer.issuerId().value()),"protocolEnrollmentProfileId",text(policy),"protocolProfileId",text("server-tls")))));
        }
    }
    /** Creates only client custody; the caller supplies its independent client unlock secret. */
    static void storeClientKeyring(Path path,char[] clientPassword,java.security.PrivateKey privateKey)throws Exception {
        try(var clientUnlock=new KeyringPassword(clientPassword.clone());var clientRing=KeyringStore.create(path,clientUnlock)) {
            clientRing.putPrivate("client","RSA",privateKey);
        }
    }
    static void cmpWire(Path root,String nonce,String runId,java.net.URI origin,String label,char[] password)throws Exception {
        root=root.toAbsolutePath().normalize();privatePath(root,true);
        if(!nonce.matches("[0-9a-f]{32}")||!runId.matches("[0-9a-f]{32}")||!text(object(root.resolve(".exercise-owner.json")),"nonce").equals(nonce)
                ||!label.equals("exercise-"+runId+"-endpoint"))throw new IllegalArgumentException("Owned CMP wire fixture required");
        var configuration=PkiServerConfigurationCodec.read(root.resolve("config/server.json"));
        if(!configuration.realm().realmId().value().equals("zeroecho-exercise-"+nonce)||!origin.getScheme().equals("https")||!origin.getHost().equals("localhost")||origin.getUserInfo()!=null||origin.getQuery()!=null||origin.getFragment()!=null
                ||!origin.getRawPath().isEmpty()||configuration.cmpListener().isEmpty()||configuration.cmpListener().orElseThrow().port()!=0&&origin.getPort()!=configuration.cmpListener().orElseThrow().port())throw new IllegalArgumentException("CMP endpoint escaped owned listener");
        var metadata=object(root.resolve("config/protocol-context.json"));
        if(!text(metadata,"protocolEnrollmentProfileId").equals("exercise-"+runId+"-protocol-policy"))throw new IllegalStateException("CMP run binding differs");
        Path custody=root.resolve("keyring/protocol-custody");
        var requester=certificate(custody.resolve("cmp-client.der"));var responder=certificate(custody.resolve("cmp-ra.der"));var authority=certificate(custody.resolve("authority.der"));
        requester.verify(authority.getPublicKey());responder.verify(authority.getPublicKey());
        byte[] transaction=new byte[16],nonceBytes=new byte[16];var random=new java.security.SecureRandom();random.nextBytes(transaction);random.nextBytes(nonceBytes);
        byte[] request;
        try(var unlock=new KeyringPassword(password.clone());var ring=KeyringStore.open(root.resolve("protocol-client/client.zek"),unlock)) {
            var builder=new org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder(new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x500.X500Name.getInstance(requester.getSubjectX500Principal().getEncoded())),new org.bouncycastle.asn1.x509.GeneralName(org.bouncycastle.asn1.x500.X500Name.getInstance(responder.getSubjectX500Principal().getEncoded())))
                    .setTransactionID(transaction).setSenderNonce(nonceBytes).setMessageTime(java.util.Date.from(Clock.systemUTC().instant()))
                    .setSenderKID(keyId(requester)).setRecipKID(keyId(responder)).addCMPCertificate(new org.bouncycastle.cert.X509CertificateHolder(requester.getEncoded()))
                    .setBody(new org.bouncycastle.asn1.cmp.PKIBody(21,new org.bouncycastle.asn1.cmp.GenMsgContent(new org.bouncycastle.asn1.cmp.InfoTypeAndValue(org.bouncycastle.asn1.cmp.CMPObjectIdentifiers.id_it_caCerts))));
            request=builder.build(new org.bouncycastle.operator.jcajce.JcaContentSignerBuilder("SHA256withRSA").build(ring.getPrivate("client"))).toASN1Structure().getEncoded();
        }
        var trusted=java.security.KeyStore.getInstance("PKCS12");trusted.load(null,null);trusted.setCertificateEntry("fixture",certificate(root.resolve("logins/web-ca.pem")));
        var trust=javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());trust.init(trusted);
        var tls=javax.net.ssl.SSLContext.getInstance("TLS");tls.init(null,trust.getTrustManagers(),random);
        try(var client=java.net.http.HttpClient.newBuilder().sslContext(tls).connectTimeout(Duration.ofSeconds(5)).build()) {
            var response=client.send(java.net.http.HttpRequest.newBuilder(origin.resolve("/pkix/"+label)).timeout(Duration.ofSeconds(15)).header("Content-Type","application/pkixcmp").POST(java.net.http.HttpRequest.BodyPublishers.ofByteArray(request)).build(),java.net.http.HttpResponse.BodyHandlers.ofInputStream());
            byte[] bytes;try(var input=response.body()){bytes=input.readNBytes(1048577);}
            if(response.statusCode()!=200||bytes.length>1048576)throw new IllegalStateException("CMP wire request rejected");
            var protectedMessage=new org.bouncycastle.cert.cmp.ProtectedPKIMessage(new org.bouncycastle.cert.cmp.GeneralPKIMessage(bytes));
            var message=protectedMessage.toASN1Structure();
            if(!protectedMessage.verify(new org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder().build(responder.getPublicKey()))||message.getBody().getType()!=22
                    ||!java.util.Arrays.equals(transaction,message.getHeader().getTransactionID().getOctets())||!java.util.Arrays.equals(nonceBytes,message.getHeader().getRecipNonce().getOctets())
                    ||!java.util.Arrays.equals(keyId(responder),message.getHeader().getSenderKID().getOctets()))throw new IllegalStateException("CMP response signature or correlation differs");
            var values=org.bouncycastle.asn1.cmp.GenRepContent.getInstance(message.getBody().getContent()).toInfoTypeAndValueArray();boolean found=false;
            for(var value:values)if(value.getInfoType().equals(org.bouncycastle.asn1.cmp.CMPObjectIdentifiers.id_it_caCerts)) {
                var chain=org.bouncycastle.asn1.ASN1Sequence.getInstance(value.getInfoValue());
                for(var entry:chain)if(java.util.Arrays.equals(authority.getEncoded(),entry.toASN1Primitive().getEncoded()))found=true;
            }
            if(!found)throw new IllegalStateException("CMP discovery did not return the frozen CA certificate");
        }
    }
    private static java.security.cert.X509Certificate certificate(Path path)throws Exception {try(var input=Files.newInputStream(path)){return (java.security.cert.X509Certificate)java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(input);}}
    private static byte[] keyId(java.security.cert.X509Certificate certificate)throws Exception {byte[] extension=certificate.getExtensionValue(org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier.getId());return extension==null?java.security.MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded()):org.bouncycastle.asn1.x509.SubjectKeyIdentifier.getInstance(org.bouncycastle.asn1.ASN1OctetString.getInstance(extension).getOctets()).getKeyIdentifier();}
    private static void write(Path path,byte[] bytes)throws Exception {Files.write(path,bytes,java.nio.file.StandardOpenOption.CREATE_NEW);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));}
    private static Map<String,PkiOperationValue> object(Path path)throws Exception {privatePath(path,false);if(Files.size(path)>1048576)throw new IllegalArgumentException("Fixture metadata exceeds bound");return ((PkiOperationValue.ObjectValue)StrictJson.parse(Files.readAllBytes(path),1048576)).fields();}
    private static PkiOperationValue.ObjectValue object(Map<String,PkiOperationValue> fields){return new PkiOperationValue.ObjectValue(fields);}
    private static PkiOperationValue.ListValue list(List<PkiOperationValue> values){return new PkiOperationValue.ListValue(values);}
    private static PkiOperationValue.Text text(String value){return new PkiOperationValue.Text(value);}
    private static PkiOperationValue.IntegerValue integer(long value){return new PkiOperationValue.IntegerValue(value);}
    private static String text(Map<String,PkiOperationValue> fields,String name){return ((PkiOperationValue.Text)fields.get(name)).value();}
    private static void privatePath(Path path,boolean directory)throws Exception {if(Files.isSymbolicLink(path)||!(directory?Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS):Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS))||!directory&&!Files.getOwner(path).equals(Files.getOwner(path.getParent()))||Files.getPosixFilePermissions(path).stream().anyMatch(p->p.name().startsWith("GROUP_")||p.name().startsWith("OTHERS_")))throw new IllegalArgumentException("Private owned fixture path required");}
}
