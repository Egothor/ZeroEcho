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
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;

/** Host-only protocol message preparation with client credentials and public certificates. */
class ExerciseLegacyEnrollmentClientHostTest {
    private static final String ENVIRONMENT="a".repeat(32), RUN="b".repeat(32);
    @Test void preparesProtectedScepAndCmpWithoutServerConfigurationOrKeys(@TempDir Path root)throws Exception {
        Files.setPosixFilePermissions(root,PosixFilePermissions.fromString("rwx------"));
        if(Security.getProvider("BC")==null)Security.addProvider(new BouncyCastleProvider());
        for(String directory:new String[]{"public","protocol-client"})Files.createDirectory(root.resolve(directory),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        write(root.resolve("client-config.json"),("{\"version\":1,\"purpose\":\"qualification\",\"environmentId\":\""+ENVIRONMENT+"\",\"realmId\":\"host-only\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        KeyPair authorityKey=key(), responderKey=key(), clientKey=key();
        X509Certificate authority=certificate("CN=Host Test CA","CN=Host Test CA",authorityKey,authorityKey,true);
        X509Certificate responder=certificate("CN=Host Test CA","CN=Host Test RA",responderKey,authorityKey,false);
        X509Certificate requester=certificate("CN=Host Test CA","CN=Host CMP Client",clientKey,authorityKey,false);
        write(root.resolve("public/authority.der"),authority.getEncoded());
        write(root.resolve("public/scep-ra.der"),responder.getEncoded());write(root.resolve("public/cmp-ra.der"),responder.getEncoded());write(root.resolve("public/cmp-client.der"),requester.getEncoded());
        char[] password="separate-client-password".toCharArray();
        try(var unlock=new KeyringPassword(password.clone());var ring=KeyringStore.create(root.resolve("protocol-client/client.zek"),unlock)) {ring.putPrivate("client","RSA",clientKey.getPrivate());}
        ExerciseLegacyEnrollmentClient.run(new String[]{root.toString(),ENVIRONMENT,RUN,"scep","initial"},password);
        var scep=new CMSSignedData(Files.readAllBytes(root.resolve("protocol-client/scep-request.der")));
        assertEquals(1,scep.getSignerInfos().size());
        var signer=scep.getSignerInfos().getSigners().iterator().next();
        X509CertificateHolder signerCertificate=scep.getCertificates().getMatches(null).iterator().next();
        assertTrue(signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(signerCertificate)));
        ExerciseLegacyEnrollmentClient.run(new String[]{root.toString(),ENVIRONMENT,RUN,"cmp","initial"},password);
        var cmp=new ProtectedPKIMessage(new GeneralPKIMessage(Files.readAllBytes(root.resolve("protocol-client/cmp-request.der"))));
        assertTrue(cmp.verify(new JcaContentVerifierProviderBuilder().build(requester.getPublicKey())));
        assertEquals(0,cmp.getBody().getType());
        assertFalse(Files.exists(root.resolve("config")));assertFalse(Files.exists(root.resolve("keyring")));
        assertEquals(PosixFilePermissions.fromString("rw-------"),Files.getPosixFilePermissions(root.resolve("protocol-client/cmp-issued.zek")));
        assertThrows(IllegalArgumentException.class,()->ExerciseLegacyEnrollmentClient.run(new String[]{root.toString(),"c".repeat(32),RUN,"cmp","initial"},password));
        assertThrows(IllegalArgumentException.class,()->ExerciseLegacyEnrollmentClient.run(new String[]{root.toString(),ENVIRONMENT,RUN,"other","initial"},password));
    }
    private static KeyPair key()throws Exception {var generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);return generator.generateKeyPair();}
    private static X509Certificate certificate(String issuer,String subject,KeyPair key,KeyPair signer,boolean ca)throws Exception {
        Instant now=Instant.now();var builder=new JcaX509v3CertificateBuilder(new X500Name(issuer),new BigInteger(128,new java.security.SecureRandom()).add(BigInteger.ONE),Date.from(now.minusSeconds(60)),Date.from(now.plusSeconds(3600)),new X500Name(subject),key.getPublic());
        builder.addExtension(Extension.basicConstraints,true,new BasicConstraints(ca));builder.addExtension(Extension.keyUsage,true,new KeyUsage(ca?KeyUsage.keyCertSign:KeyUsage.digitalSignature|KeyUsage.keyEncipherment));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())));
    }
    private static void write(Path path,byte[] content)throws Exception {Files.write(path,content);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));}
}
