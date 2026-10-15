/*******************************************************************************
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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.Optional;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessage;
import org.bouncycastle.cert.cmp.ProtectedPKIMessageBuilder;
import org.bouncycastle.cert.crmf.CertificateRequestMessageBuilder;
import org.bouncycastle.cert.crmf.Control;
import org.bouncycastle.operator.GenericKey;
import org.bouncycastle.operator.MacCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;

/** Independent BC wire client; it never uses ZeroEcho's production CMP codec. */
final class CmpTestClient {
    static final BigInteger REQUEST_ID = BigInteger.valueOf(7);
    private CmpTestClient() { }

    static PKIBody enrollment(KeyPair subject, X509Certificate predecessor) throws Exception {
        CertificateRequestMessageBuilder builder = new CertificateRequestMessageBuilder(REQUEST_ID)
                .setSubject(new X500Name("CN=localhost")).setPublicKey(SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded()));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
        if (predecessor != null) {
            builder.addControl(new Control() {
                @Override public org.bouncycastle.asn1.ASN1ObjectIdentifier getType() { return CRMFObjectIdentifiers.id_regCtrl_oldCertID; }
                @Override public ASN1Encodable getValue() { return new CertId(new GeneralName(
                        X500Name.getInstance(predecessor.getIssuerX500Principal().getEncoded())), predecessor.getSerialNumber()); }
            });
        }
        return new PKIBody(predecessor == null ? 0 : 7, new CertReqMessages(builder
                .setProofOfPossessionSigningKeySigner(new JcaContentSignerBuilder("SHA256withRSA").build(subject.getPrivate()))
                .build().toASN1Structure()));
    }

    static PKIBody poll() { return new PKIBody(25, new PollReqContent(REQUEST_ID)); }
    static PKIBody confirmation(X509Certificate certificate, boolean accepted) throws Exception {
        CertStatus status = new CertStatus(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()), REQUEST_ID,
                new PKIStatusInfo(accepted ? PKIStatus.granted : PKIStatus.rejection));
        return new PKIBody(24, CertConfirmContent.getInstance(new DERSequence(status)));
    }
    static PKIBody revoke(X509Certificate certificate) {
        return new PKIBody(11, new RevReqContent(new RevDetails(new CertTemplateBuilder()
                .setSerialNumber(new ASN1Integer(certificate.getSerialNumber()))
                .setIssuer(X500Name.getInstance(certificate.getIssuerX500Principal().getEncoded())).build())));
    }
    static PKIBody discovery() { return new PKIBody(21, new GenMsgContent(new InfoTypeAndValue(CMPObjectIdentifiers.id_it_caCerts))); }

    static byte[] signed(PKIBody body, byte[] transaction, byte[] nonce, byte[] recipientNonce, KeyPair signer,
            X509Certificate certificate, X509Certificate responder, boolean implicit) throws Exception {
        ProtectedPKIMessageBuilder builder = builder(body, transaction, nonce, recipientNonce,
                X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded()),
                X500Name.getInstance(responder.getSubjectX500Principal().getEncoded()))
                .setSenderKID(keyId(certificate)).setRecipKID(keyId(responder))
                .addCMPCertificate(new X509CertificateHolder(certificate.getEncoded()));
        if (implicit) builder.addGeneralInfo(new InfoTypeAndValue(CMPObjectIdentifiers.it_implicitConfirm, DERNull.INSTANCE));
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(signer.getPrivate())).toASN1Structure().getEncoded();
    }

    static byte[] pbm(PKIBody body, byte[] transaction, byte[] nonce, byte[] recipientNonce,
            byte[] secret, X509Certificate authority) throws Exception {
        PBMParameter parameters = new PBMParameter(nonce(41), new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256), 1000,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256));
        return builder(body, transaction, nonce, recipientNonce, new X500Name("CN=PBM requester"),
                X500Name.getInstance(authority.getSubjectX500Principal().getEncoded()))
                .setSenderKID(new byte[] {1, 2}).build(mac(parameters, secret)).toASN1Structure().getEncoded();
    }

    static Reply signatureResponse(byte[] encoded, byte[] transaction, byte[] requestNonce, X509Certificate responder) throws Exception {
        ProtectedPKIMessage protectedMessage = new ProtectedPKIMessage(new GeneralPKIMessage(encoded));
        assertTrue(protectedMessage.verify(new JcaContentVerifierProviderBuilder().build(responder.getPublicKey())));
        PKIMessage message = protectedMessage.toASN1Structure();
        assertArrayEquals(keyId(responder), message.getHeader().getSenderKID().getOctets());
        return reply(message, transaction, requestNonce);
    }

    static Reply pbmResponse(byte[] encoded, byte[] transaction, byte[] requestNonce, byte[] secret) throws Exception {
        PKIMessage message = PKIMessage.getInstance(encoded);
        assertEquals(CMPObjectIdentifiers.passwordBasedMac, message.getHeader().getProtectionAlg().getAlgorithm());
        PBMParameter parameters = PBMParameter.getInstance(message.getHeader().getProtectionAlg().getParameters());
        assertEquals(NISTObjectIdentifiers.id_sha256, parameters.getOwf().getAlgorithm());
        assertEquals(PKCSObjectIdentifiers.id_hmacWithSHA256, parameters.getMac().getAlgorithm());
        assertEquals(1000, parameters.getIterationCount().intValueExact());
        MacCalculator calculator = mac(parameters, secret);
        calculator.getOutputStream().write(new DERSequence(new ASN1Encodable[] {message.getHeader(), message.getBody()}).getEncoded());
        assertArrayEquals(calculator.getMac(), message.getProtection().getOctets());
        return reply(message, transaction, requestNonce);
    }

    private static Reply reply(PKIMessage message, byte[] transaction, byte[] requestNonce) {
        assertArrayEquals(transaction, message.getHeader().getTransactionID().getOctets());
        assertArrayEquals(requestNonce, message.getHeader().getRecipNonce().getOctets());
        assertTrue(message.getHeader().getSenderNonce().getOctets().length >= 16);
        return new Reply(message);
    }
    static byte[] nonce(int value) { byte[] result = new byte[16]; Arrays.fill(result, (byte) value); return result; }
    private static byte[] keyId(X509Certificate certificate) throws Exception {
        byte[] extension = certificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        return extension == null ? MessageDigest.getInstance("SHA-256").digest(certificate.getPublicKey().getEncoded())
                : SubjectKeyIdentifier.getInstance(org.bouncycastle.asn1.ASN1OctetString.getInstance(extension).getOctets()).getKeyIdentifier();
    }
    private static ProtectedPKIMessageBuilder builder(PKIBody body, byte[] transaction, byte[] nonce, byte[] recipientNonce,
            X500Name sender, X500Name recipient) {
        ProtectedPKIMessageBuilder builder = new ProtectedPKIMessageBuilder(new GeneralName(sender), new GeneralName(recipient))
                .setTransactionID(transaction).setSenderNonce(nonce).setMessageTime(Date.from(Instant.now())).setBody(body);
        if (recipientNonce != null) builder.setRecipNonce(recipientNonce);
        return builder;
    }
    private static MacCalculator mac(PBMParameter parameters, byte[] secret) throws Exception {
        byte[] salt = parameters.getSalt().getOctets();
        byte[] initial = Arrays.copyOf(secret, secret.length + salt.length);
        System.arraycopy(salt, 0, initial, secret.length, salt.length);
        byte[] key = initial;
        for (int i = 0; i < parameters.getIterationCount().intValueExact(); i++) key = MessageDigest.getInstance("SHA-256").digest(key);
        Mac mac = Mac.getInstance("HmacSHA256"); mac.init(new SecretKeySpec(key, "HmacSHA256"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        return new MacCalculator() {
            @Override public AlgorithmIdentifier getAlgorithmIdentifier() { return new AlgorithmIdentifier(CMPObjectIdentifiers.passwordBasedMac, parameters); }
            @Override public GenericKey getKey() { throw new UnsupportedOperationException(); }
            @Override public OutputStream getOutputStream() { return output; }
            @Override public byte[] getMac() { return mac.doFinal(output.toByteArray()); }
        };
    }

    record Reply(PKIMessage message) {
        int type() { return message.getBody().getType(); }
        byte[] nonce() { return message.getHeader().getSenderNonce().getOctets(); }
        boolean pending() {
            return type() == 26 || (type() == 1 || type() == 3 || type() == 8)
                    && CertRepMessage.getInstance(message.getBody().getContent()).getResponse()[0].getStatus().getStatus().intValueExact() == 3;
        }
        Optional<X509Certificate> certificate() throws Exception {
            if (type() != 1 && type() != 3 && type() != 8) return Optional.empty();
            CertResponse response = CertRepMessage.getInstance(message.getBody().getContent()).getResponse()[0];
            assertEquals(REQUEST_ID, response.getCertReqId().getValue());
            if (response.getCertifiedKeyPair() == null) return Optional.empty();
            byte[] encoded = response.getCertifiedKeyPair().getCertOrEncCert().getCertificate().getEncoded();
            return Optional.of((X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded)));
        }
        @Override public String toString() { return "CmpTestClient.Reply[redacted]"; }
    }
}
