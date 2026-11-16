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

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.*;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.http.StrictJson;

/**
 * Independent host BC SCEP/CMP client for a declared qualification environment.
 * Writes only public protocol messages and password-protected client keyrings.
 * It never opens server signing keys or bypasses enrollment approval policy.
 */
public final class ExerciseLegacyEnrollmentClient {
    private static final SecureRandom RANDOM=new SecureRandom();
    private static final BigInteger REQUEST_ID=BigInteger.valueOf(7);
    private static final String PREFIX="2.16.840.1.113733.1.9.";
    private ExerciseLegacyEnrollmentClient() { }

    /**
     * Runs one bounded offline client phase; reads the keyring password from stdin.
     * @param arguments private client directory, environment ID, run ID, protocol and phase
     * @throws Exception on ownership, protection, transaction or certificate failure
     */
    public static void main(String[] arguments) throws Exception {
        char[] password=new java.io.BufferedReader(new java.io.InputStreamReader(System.in,java.nio.charset.StandardCharsets.UTF_8)).readLine().toCharArray();
        try { run(arguments,password); } finally { Arrays.fill(password,'\0'); }
    }

    /**
     * Runs an independent SCEP/CMP client phase using only its manifest, public certificates and client custody.
     *
     * @param arguments exact client-root, environment nonce, run identity, protocol and phase arguments
     * @param password independent client keyring unlock password
     * @throws Exception if arguments/ownership, client configuration, protected wire processing or external interface checks fail
     */
    static void run(String[] arguments,char[] password) throws Exception {
        if(arguments.length!=5) throw new IllegalArgumentException("Five host client arguments required");
        Path root=Path.of(arguments[0]).toAbsolutePath().normalize();
        String nonce=arguments[1], runId=arguments[2], protocol=arguments[3], phase=arguments[4];
        require(nonce.matches("[0-9a-f]{32}")&&runId.matches("[0-9a-f]{32}"),"Invalid client environment identity");
        require(protocol.equals("scep")||protocol.equals("cmp"),"Unsupported legacy protocol");
        privatePath(root,true);
        var configuration=object(root.resolve("client-config.json"));
        require(((PkiOperationValue.IntegerValue)configuration.get("version")).value()==1,"Unsupported client manifest version");
        require(text(configuration,"purpose").equals("qualification"),"Client manifest is not a qualification environment");
        require(nonce.equals(text(configuration,"environmentId")),"Client environment identity mismatch");
        require(text(configuration,"realmId").matches("[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"),"Invalid client realm identity");
        privatePath(root.resolve("public"),true);
        Path client=root.resolve("protocol-client");
        if(!Files.exists(client))Files.createDirectory(client,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        privatePath(client,true);
        if(Security.getProvider("BC")==null)Security.addProvider(new BouncyCastleProvider());
        Path statePath=client.resolve(protocol+"-state.json"), request=client.resolve(protocol+"-request.der");
        Path keyPath=client.resolve(protocol+"-issued.zek");
        X509Certificate authority=certificate(root.resolve("public/authority.der"));
        X509Certificate responder=certificate(root.resolve("public/"+protocol+"-ra.der"));
        authority.verify(authority.getPublicKey());authority.checkValidity();
        responder.verify(authority.getPublicKey());responder.checkValidity();
        if(phase.equals("initial")&&Files.exists(statePath)) {
            require(text(object(statePath),"runId").equals(runId),"Client state belongs to another run");
            privatePath(request,false);System.out.println("LEGACY_CLIENT_READY");return;
        }
        KeyPair subject;
        if(phase.equals("initial")) {
            require(!Files.exists(keyPath),"Uncertain client key initialization cannot be repeated");
            var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048,RANDOM);subject=generator.generateKeyPair();
            try(var unlock=new KeyringPassword(password.clone());var ring=KeyringStore.create(keyPath,unlock)) {
                ring.putPrivate("subject.prv","RSA",subject.getPrivate());ring.putPublic("subject.pub","RSA",subject.getPublic());
            }
        } else {
            privatePath(keyPath,false);
            try(var unlock=new KeyringPassword(password.clone());var ring=KeyringStore.open(keyPath,unlock)) {
                subject=new KeyPair(ring.getPublic("subject.pub"),ring.getPrivate("subject.prv"));
            }
        }
        Map<String,PkiOperationValue> state=phase.equals("initial")?new LinkedHashMap<>():new LinkedHashMap<>(object(statePath));
        if(!phase.equals("initial"))require(text(state,"runId").equals(runId),"Client run mismatch");
        if(phase.equals("verify")) {
            byte[] response=bounded(client.resolve(protocol+"-response.der"));
            byte[] expected=decode(text(state,"nonce"));
            X509Certificate issued=null;String status;
            if(protocol.equals("scep")) {
                var signed=new CMSSignedData(response);
                if(signed.getSignedContent()==null)signed=new CMSSignedData(new CMSProcessableByteArray(new byte[0]),response);
                require(signed.getSignerInfos().size()==1,"Unexpected SCEP response signer count");
                var signer=signed.getSignerInfos().getSigners().iterator().next();
                require(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(responder)),"Invalid SCEP response signature");
                require(Arrays.equals(expected,ASN1OctetString.getInstance(signer.getSignedAttributes().get(oid(6)).getAttrValues().getObjectAt(0)).getOctets()),"SCEP recipient nonce mismatch");
                require(text(state,"transaction").equals(ASN1PrintableString.getInstance(signer.getSignedAttributes().get(oid(7)).getAttrValues().getObjectAt(0)).getString()),"SCEP transaction mismatch");
                status=ASN1PrintableString.getInstance(signer.getSignedAttributes().get(oid(3)).getAttrValues().getObjectAt(0)).getString();
                if(status.equals("0")) {
                    var envelope=new CMSEnvelopedData((byte[])signed.getSignedContent().getContent());
                    require(envelope.getRecipientInfos().size()==1,"Unexpected SCEP encrypted recipient count");
                    require(envelope.getEncryptionAlgOID().equals(CMSAlgorithm.AES128_CBC.getId()),"Unexpected SCEP response encryption algorithm");
                    byte[] inner=envelope.getRecipientInfos().getRecipients().iterator().next().getContent(new JceKeyTransEnvelopedRecipient(subject.getPrivate()).setProvider("BC"));
                    var certificates=new CMSSignedData(inner);
                    require(certificates.getSignerInfos().size()==0,"Issued SCEP certificate bag has unexpected signer");
                    for(var holder:certificates.getCertificates().getMatches(null)) {
                        X509Certificate candidate=new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
                        if(Arrays.equals(candidate.getPublicKey().getEncoded(),subject.getPublic().getEncoded())) {
                            require(issued==null,"Ambiguous issued SCEP certificate");issued=candidate;
                        }
                    }
                } else require(status.equals("3"),"SCEP enrollment rejected");
            } else {
                var protectedMessage=new ProtectedPKIMessage(new GeneralPKIMessage(response));
                require(protectedMessage.verify(new JcaContentVerifierProviderBuilder().build(responder.getPublicKey())),"Invalid CMP response signature");
                var message=protectedMessage.toASN1Structure();
                require(Arrays.equals(decode(text(state,"transaction")),message.getHeader().getTransactionID().getOctets()),"CMP transaction mismatch");
                require(Arrays.equals(expected,message.getHeader().getRecipNonce().getOctets()),"CMP recipient nonce mismatch");
                require(Arrays.equals(keyId(responder),message.getHeader().getSenderKID().getOctets()),"CMP responder key mismatch");
                byte[] sender=message.getHeader().getSenderNonce().getOctets();require(sender.length>=16&&sender.length<=64,"Invalid CMP sender nonce");
                state.put("recipientNonce",new PkiOperationValue.Text(encode(sender)));
                int type=message.getBody().getType();
                if(type==19)status="CONFIRMED";
                else if(type==26)status="3";
                else {
                    require(type==1||type==3||type==8,"Unexpected CMP response body");
                    var result=CertRepMessage.getInstance(message.getBody().getContent()).getResponse();
                    require(result.length==1&&result[0].getCertReqId().getValue().equals(REQUEST_ID),"CMP request identity mismatch");
                    int disposition=result[0].getStatus().getStatus().intValueExact();
                    require(disposition==0||disposition==1||disposition==3,"CMP enrollment rejected");
                    status=disposition==3?"3":"0";
                    if(status.equals("0"))issued=certificate(result[0].getCertifiedKeyPair().getCertOrEncCert().getCertificate().getEncoded());
                }
            }
            String outcome=status.equals("3")?"PENDING":status.equals("CONFIRMED")?"CONFIRMED":"ISSUED";
            var result=new LinkedHashMap<String,PkiOperationValue>();result.put("state",new PkiOperationValue.Text(outcome));
            if(outcome.equals("ISSUED")) {
                require(issued!=null,"Response omitted issued certificate");issued.verify(authority.getPublicKey());issued.checkValidity();
                require(issued.getBasicConstraints()<0&&Arrays.equals(issued.getPublicKey().getEncoded(),subject.getPublic().getEncoded()),"Issued certificate does not match the owned subject key");
                require(issued.getSubjectX500Principal().equals(new javax.security.auth.x500.X500Principal("CN=localhost")),"Issued certificate subject differs from the request");
                require(issued.getSubjectAlternativeNames()!=null&&issued.getSubjectAlternativeNames().stream().anyMatch(name->Integer.valueOf(2).equals(name.get(0))&&"localhost".equals(name.get(1))),"Issued certificate DNS name differs from the request");
                byte[] challenge=random();var signature=java.security.Signature.getInstance("SHA256withRSA");signature.initSign(subject.getPrivate(),RANDOM);signature.update(challenge);byte[] proof=signature.sign();
                signature.initVerify(issued.getPublicKey());signature.update(challenge);require(signature.verify(proof),"Issued private-key proof failed");
                write(client.resolve(protocol+"-certificate.der"),issued.getEncoded());
                result.put("certificateSha256",new PkiOperationValue.Text(hash(issued.getEncoded())));
                result.put("spkiSha256",new PkiOperationValue.Text(hash(subject.getPublic().getEncoded())));
            }
            write(client.resolve(protocol+"-result.json"),StrictJson.encode(new PkiOperationValue.ObjectValue(result)));
        } else {
            require(phase.equals("initial")||phase.equals("poll")||phase.equals("confirm"),"Unsupported legacy client phase");
            byte[] nonceBytes=random();state.put("nonce",new PkiOperationValue.Text(encode(nonceBytes)));state.put("runId",new PkiOperationValue.Text(runId));
            byte[] payload;
            if(protocol.equals("scep")) {
                require(!phase.equals("confirm"),"SCEP has no CMP confirmation phase");
                X509Certificate requester;
                Path requesterPath=client.resolve("scep-requester.der");
                if(phase.equals("initial")){requester=selfSigned(subject);write(requesterPath,requester.getEncoded());state.put("transaction",new PkiOperationValue.Text("exercise-"+runId+"-scep"));}
                else requester=certificate(requesterPath);
                byte[] body=phase.equals("initial")?csr(subject,"exercise-"+runId+"-scep"):new DERSequence(new ASN1Encodable[]{X500Name.getInstance(authority.getSubjectX500Principal().getEncoded()),new X500Name("CN=localhost")}).getEncoded();
                payload=scep(body,text(state,"transaction"),nonceBytes,phase.equals("initial")?19:20,subject,requester,responder);
            } else {
                X509Certificate requester=certificate(root.resolve("public/cmp-client.der"));
                KeyPair signer;
                try(var unlock=new KeyringPassword(password.clone());var ring=KeyringStore.open(client.resolve("client.zek"),unlock)) {
                    signer=new KeyPair(requester.getPublicKey(),ring.getPrivate("client"));
                }
                PKIBody body;
                if(phase.equals("initial")) {
                    state.put("transaction",new PkiOperationValue.Text(encode(random())));
                    var requestBuilder=new CertificateRequestMessageBuilder(REQUEST_ID).setSubject(new X500Name("CN=localhost")).setPublicKey(SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded()));
                    requestBuilder.addExtension(Extension.subjectAlternativeName,false,new GeneralNames(new GeneralName(GeneralName.dNSName,"localhost")));
                    body=new PKIBody(0,new CertReqMessages(requestBuilder.setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA").build(subject.getPrivate())).build().toASN1Structure()));
                } else if(phase.equals("poll"))body=new PKIBody(25,new PollReqContent(REQUEST_ID));
                else {X509Certificate issued=certificate(client.resolve("cmp-certificate.der"));body=new PKIBody(24,CertConfirmContent.getInstance(new DERSequence(new CertStatus(MessageDigest.getInstance("SHA-256").digest(issued.getEncoded()),REQUEST_ID,new PKIStatusInfo(PKIStatus.granted)))));}
                var builder=new ProtectedPKIMessageBuilder(new GeneralName(X500Name.getInstance(requester.getSubjectX500Principal().getEncoded())),new GeneralName(X500Name.getInstance(responder.getSubjectX500Principal().getEncoded())))
                    .setTransactionID(decode(text(state,"transaction"))).setSenderNonce(nonceBytes).setMessageTime(new Date()).setSenderKID(keyId(requester)).setRecipKID(keyId(responder)).addCMPCertificate(new X509CertificateHolder(requester.getEncoded())).setBody(body);
                if(!phase.equals("initial"))builder.setRecipNonce(decode(text(state,"recipientNonce")));
                payload=builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())).toASN1Structure().getEncoded();
            }
            write(request,payload);
        }
        write(statePath,StrictJson.encode(new PkiOperationValue.ObjectValue(state)));
        System.out.println("LEGACY_CLIENT_READY");
    }

    private static byte[] scep(byte[] plaintext,String transaction,byte[] nonce,int type,KeyPair key,X509Certificate signer,X509Certificate recipient)throws Exception {
        var envelope=new CMSEnvelopedDataGenerator();envelope.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(recipient).setProvider("BC"));
        byte[] encrypted=envelope.generate(new CMSProcessableByteArray(plaintext),new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES128_CBC).setProvider("BC").build()).getEncoded();
        var attributes=new ASN1EncodableVector();attributes.add(new Attribute(oid(2),new DERSet(new DERPrintableString(Integer.toString(type)))));attributes.add(new Attribute(oid(7),new DERSet(new DERPrintableString(transaction))));attributes.add(new Attribute(oid(5),new DERSet(new DEROctetString(nonce))));
        var output=new CMSSignedDataGenerator();output.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes))).build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(key.getPrivate()),signer));
        output.addCertificates(new org.bouncycastle.cert.jcajce.JcaCertStore(List.of(signer)));return output.generate(new CMSProcessableByteArray(encrypted),true).getEncoded();
    }
    private static byte[] csr(KeyPair key,String challenge)throws Exception {
        var builder=new JcaPKCS10CertificationRequestBuilder(new javax.security.auth.x500.X500Principal("CN=localhost"),key.getPublic());
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword,new DERUTF8String(challenge));
        var extensions=new ExtensionsGenerator();extensions.addExtension(Extension.subjectAlternativeName,false,new GeneralNames(new GeneralName(GeneralName.dNSName,"localhost")));
        builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,extensions.generate());return builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(key.getPrivate())).getEncoded();
    }
    private static X509Certificate selfSigned(KeyPair key)throws Exception {
        Instant now=Instant.now();var name=new X500Name("CN=localhost");
        var builder=new JcaX509v3CertificateBuilder(name,new BigInteger(159,RANDOM).add(BigInteger.ONE),Date.from(now.minusSeconds(60)),Date.from(now.plusSeconds(3600)),name,key.getPublic());
        builder.addExtension(Extension.basicConstraints,true,new BasicConstraints(false));builder.addExtension(Extension.keyUsage,true,new KeyUsage(KeyUsage.digitalSignature|KeyUsage.keyEncipherment));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(key.getPrivate())));
    }
    private static ASN1ObjectIdentifier oid(int suffix){return new ASN1ObjectIdentifier(PREFIX+suffix);}
    private static byte[] keyId(X509Certificate certificate)throws Exception {byte[] extension=certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());return extension==null?MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded()):SubjectKeyIdentifier.getInstance(ASN1OctetString.getInstance(extension).getOctets()).getKeyIdentifier();}
    private static byte[] random(){byte[] bytes=new byte[16];RANDOM.nextBytes(bytes);return bytes;}
    private static String encode(byte[] value){return Base64.getEncoder().encodeToString(value);}
    private static byte[] decode(String value){return Base64.getDecoder().decode(value);}
    private static String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
    private static X509Certificate certificate(Path path)throws Exception{return certificate(bounded(path));}
    private static X509Certificate certificate(byte[] bytes)throws Exception{return (X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(bytes));}
    private static Map<String,PkiOperationValue> object(Path path)throws Exception{return ((PkiOperationValue.ObjectValue)StrictJson.parse(bounded(path),1048576)).fields();}
    private static String text(Map<String,PkiOperationValue> object,String name){return ((PkiOperationValue.Text)object.get(name)).value();}
    private static byte[] bounded(Path path)throws Exception{privatePath(path,false);require(Files.size(path)<=1048576,"Client input exceeds bound");return Files.readAllBytes(path);}
    private static void write(Path path,byte[] bytes)throws Exception{require(!Files.isSymbolicLink(path),"Client output is a symlink");Path temporary=path.resolveSibling("."+path.getFileName()+".new");Files.write(temporary,bytes,java.nio.file.StandardOpenOption.CREATE_NEW);Files.setPosixFilePermissions(temporary,PosixFilePermissions.fromString("rw-------"));Files.move(temporary,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);}
    private static void privatePath(Path path,boolean directory)throws Exception{require(!Files.isSymbolicLink(path)&&(directory?Files.isDirectory(path,LinkOption.NOFOLLOW_LINKS):Files.isRegularFile(path,LinkOption.NOFOLLOW_LINKS)),"Owned private path required");require(Files.getPosixFilePermissions(path).stream().noneMatch(p->p.name().startsWith("GROUP_")||p.name().startsWith("OTHERS_")),"Client path is not private");}
    private static void require(boolean condition,String message){if(!condition)throw new IllegalArgumentException(message);}
}
