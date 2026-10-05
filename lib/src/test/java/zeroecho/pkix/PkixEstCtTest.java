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
package zeroecho.pkix;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.junit.jupiter.api.Test;

import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.csr.CsrAttribute;
import zeroecho.pkix.ct.PreCertificateResult;
import zeroecho.pkix.ct.SignedCertificateTimestamp;
import zeroecho.pkix.sign.ContentSigner;

/** Tests for EST (RFC 7030) encoding and Certificate Transparency (RFC 9162) operations in the PKIX API. */
class PkixEstCtTest {

    private static final AlgorithmIdentifier SHA256_RSA =
            AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");
    private static final AlgorithmIdentifier SHA256_ECDSA =
            AlgorithmIdentifier.absent("1.2.840.10045.4.3.2");
    private static final String CT_POISON_OID = "1.3.6.1.4.1.11129.2.4.3";
    private static final String CT_SCT_LIST_OID = "1.3.6.1.4.1.11129.2.4.2";

    private static KeyPair rsa2048() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static KeyPair ec256() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(256);
        return gen.generateKeyPair();
    }

    private static ContentSigner rsaSigner(KeyPair kp) {
        return Pkix.signer(kp.getPrivate(), SHA256_RSA);
    }

    private static ContentSigner ecSigner(KeyPair kp) {
        return Pkix.signer(kp.getPrivate(), SHA256_ECDSA);
    }

    private static X509Certificate selfSignedRsa() throws Exception {
        KeyPair ca = rsa2048();
        X500Principal dn = new X500Principal("CN=Test CA");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE)
                .subject(dn).issuer(dn)
                .validity(now, now.plus(365, ChronoUnit.DAYS))
                .publicKey(ca.getPublic())
                .basicConstraints(BasicConstraints.ca(0), true)
                .build(rsaSigner(ca));
    }

    // -------------------------------------------------------------------------
    // parseCsr
    // -------------------------------------------------------------------------

    @Test
    void parseCsr_derInput_roundtrip() throws Exception {
        KeyPair leaf = rsa2048();
        X500Principal subject = new X500Principal("CN=est-test.example.com");
        CertificationRequest original = Pkix.certificationRequestBuilder()
                .subject(subject).publicKey(leaf.getPublic()).build(rsaSigner(leaf));

        CertificationRequest parsed = Pkix.parseCsr(original.encoded());

        assertTrue(parsed.verifySelfSignature());
        assertEquals(subject, parsed.subject());
        assertEquals(leaf.getPublic(), parsed.publicKey());
    }

    @Test
    void parseCsr_pemInput_roundtrip() throws Exception {
        KeyPair leaf = ec256();
        CertificationRequest original = Pkix.certificationRequestBuilder()
                .subject(new X500Principal("CN=pem-test")).publicKey(leaf.getPublic())
                .build(ecSigner(leaf));

        String b64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(original.encoded());
        String pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + b64
                + "\n-----END CERTIFICATE REQUEST-----\n";

        CertificationRequest parsed = Pkix.parseCsr(pem.getBytes(StandardCharsets.US_ASCII));

        assertTrue(parsed.verifySelfSignature());
        assertEquals(leaf.getPublic(), parsed.publicKey());
    }

    @Test
    void parseCsr_corruptedSignature_throwsCertificationRequestException() throws Exception {
        KeyPair leaf = rsa2048();
        CertificationRequest original = Pkix.certificationRequestBuilder()
                .subject(new X500Principal("CN=corrupt")).publicKey(leaf.getPublic())
                .build(rsaSigner(leaf));

        byte[] der = original.encoded().clone();
        der[der.length - 1] ^= (byte) 0xFF;

        assertThrows(CertificationRequestException.class, () -> Pkix.parseCsr(der));
    }

    @Test
    void parseCsr_invalidDer_throwsCertificationRequestException() {
        byte[] garbage = {0x00, 0x01, 0x02, 0x03, 0x04};
        assertThrows(CertificationRequestException.class, () -> Pkix.parseCsr(garbage));
    }

    // -------------------------------------------------------------------------
    // encodeCertsOnly
    // -------------------------------------------------------------------------

    @Test
    void encodeCertsOnly_singleCert_decodesAsExpected() throws Exception {
        X509Certificate cert = selfSignedRsa();
        byte[] encoded = Pkix.encodeCertsOnly(List.of(cert));

        CMSSignedData signedData = new CMSSignedData(encoded);
        assertTrue(signedData.getSignerInfos().getSigners().isEmpty(), "no signers in certs-only");
        assertEquals(1, signedData.getCertificates().getMatches(null).size(), "one certificate");
    }

    @Test
    void encodeCertsOnly_multipleChain_preservesOrder() throws Exception {
        X509Certificate cert1 = selfSignedRsa();
        X509Certificate cert2 = selfSignedRsa();
        byte[] encoded = Pkix.encodeCertsOnly(List.of(cert1, cert2));

        CMSSignedData signedData = new CMSSignedData(encoded);
        assertEquals(2, signedData.getCertificates().getMatches(null).size());
    }

    // -------------------------------------------------------------------------
    // encodeCsrAttrs
    // -------------------------------------------------------------------------

    @Test
    void encodeCsrAttrs_oidOnly_decodesCorrectly() throws Exception {
        String rsaEncryptionOid = "1.2.840.113549.1.1.1";
        List<CsrAttribute> attrs = List.of(new CsrAttribute(rsaEncryptionOid, List.of()));

        byte[] encoded = Pkix.encodeCsrAttrs(attrs);

        assertNotNull(encoded);
        assertTrue(encoded.length > 0);
        // Parse back: should be a DER SEQUENCE containing an OID
        org.bouncycastle.asn1.ASN1Sequence seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(
                ASN1Primitive.fromByteArray(encoded));
        assertEquals(1, seq.size());
        assertEquals(rsaEncryptionOid,
                org.bouncycastle.asn1.ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0)).getId());
    }

    @Test
    void encodeCsrAttrs_empty_encodesEmptySequence() throws Exception {
        byte[] encoded = Pkix.encodeCsrAttrs(List.of());

        org.bouncycastle.asn1.ASN1Sequence seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(
                ASN1Primitive.fromByteArray(encoded));
        assertEquals(0, seq.size());
    }

    // -------------------------------------------------------------------------
    // encryptPrivateKeyForRecipient
    // -------------------------------------------------------------------------

    @Test
    void encryptPrivateKeyForRecipient_rsaRecipient_decryptionRoundtrip() throws Exception {
        KeyPair recipient = rsa2048();
        X500Principal dn = new X500Principal("CN=RSA Recipient");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate recipientCert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.TWO)
                .subject(dn).issuer(dn)
                .validity(now, now.plus(365, ChronoUnit.DAYS))
                .publicKey(recipient.getPublic())
                .build(rsaSigner(recipient));

        KeyPair subjectKey = ec256();
        byte[] pkcs8Bytes = subjectKey.getPrivate().getEncoded();

        byte[] cmsEnveloped = Pkix.encryptPrivateKeyForRecipient(pkcs8Bytes, recipientCert);
        assertNotNull(cmsEnveloped);
        assertTrue(cmsEnveloped.length > 0);

        CMSEnvelopedData enveloped = new CMSEnvelopedData(cmsEnveloped);
        byte[] decrypted = enveloped.getRecipientInfos().getRecipients().iterator().next()
                .getContent(new JceKeyTransEnvelopedRecipient(recipient.getPrivate()).setProvider("BC"));
        assertArrayEquals(pkcs8Bytes, decrypted);
    }

    @Test
    void encryptPrivateKeyForRecipient_ecRecipient_decryptionRoundtrip() throws Exception {
        KeyPair recipient = ec256();
        X500Principal dn = new X500Principal("CN=EC Recipient");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate recipientCert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.valueOf(3))
                .subject(dn).issuer(dn)
                .validity(now, now.plus(365, ChronoUnit.DAYS))
                .publicKey(recipient.getPublic())
                .build(ecSigner(recipient));

        byte[] pkcs8Bytes = rsa2048().getPrivate().getEncoded();

        byte[] cmsEnveloped = Pkix.encryptPrivateKeyForRecipient(pkcs8Bytes, recipientCert);
        assertNotNull(cmsEnveloped);

        CMSEnvelopedData enveloped = new CMSEnvelopedData(cmsEnveloped);
        byte[] decrypted = enveloped.getRecipientInfos().getRecipients().iterator().next()
                .getContent(new JceKeyAgreeEnvelopedRecipient(recipient.getPrivate()).setProvider("BC"));
        assertArrayEquals(pkcs8Bytes, decrypted);
    }

    // -------------------------------------------------------------------------
    // buildPreCertificate
    // -------------------------------------------------------------------------

    @Test
    void buildPreCertificate_poisonExtensionPresentAndCritical() throws Exception {
        KeyPair ca = rsa2048();
        X500Principal dn = new X500Principal("CN=CT Test CA");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate caCert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE)
                .subject(dn).issuer(dn)
                .validity(now, now.plus(365, ChronoUnit.DAYS))
                .publicKey(ca.getPublic())
                .basicConstraints(BasicConstraints.ca(0), true)
                .build(rsaSigner(ca));

        byte[] tbsDer = caCert.getTBSCertificate();
        List<byte[]> chain = List.of(caCert.getEncoded());

        PreCertificateResult result = Pkix.buildPreCertificate(tbsDer, chain, rsaSigner(ca));

        assertNotNull(result.preCertDer());
        assertEquals(1, result.chainDer().size());

        X509Certificate preCert = Pkix.parseCertificate(result.preCertDer());
        byte[] poisonValue = preCert.getExtensionValue(CT_POISON_OID);
        assertNotNull(poisonValue, "CT poison extension must be present");
        assertTrue(preCert.getCriticalExtensionOIDs().contains(CT_POISON_OID),
                "CT poison extension must be critical");
    }

    // -------------------------------------------------------------------------
    // embedScts
    // -------------------------------------------------------------------------

    @Test
    void embedScts_replacesPoisonWithSctListExtension() throws Exception {
        KeyPair ca = rsa2048();
        X500Principal dn = new X500Principal("CN=SCT Test CA");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate caCert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE)
                .subject(dn).issuer(dn)
                .validity(now, now.plus(365, ChronoUnit.DAYS))
                .publicKey(ca.getPublic())
                .basicConstraints(BasicConstraints.ca(0), true)
                .build(rsaSigner(ca));

        byte[] tbsDer = caCert.getTBSCertificate();
        PreCertificateResult preResult = Pkix.buildPreCertificate(
                tbsDer, List.of(caCert.getEncoded()), rsaSigner(ca));

        byte[] preTbsDer = Pkix.parseCertificate(preResult.preCertDer()).getTBSCertificate();

        byte[] fakeLogId = new byte[SignedCertificateTimestamp.LOG_ID_LENGTH];
        Arrays.fill(fakeLogId, (byte) 0xAB);
        byte[] fakeSig = new byte[64];
        Arrays.fill(fakeSig, (byte) 0xCD);
        SignedCertificateTimestamp sct = new SignedCertificateTimestamp(
                0, fakeLogId, Instant.now(), new byte[0], "SHA256withECDSA", fakeSig);

        byte[] modifiedTbsDer = Pkix.embedScts(preTbsDer, List.of(sct));

        TBSCertificate modifiedTbs = TBSCertificate.getInstance(
                ASN1Primitive.fromByteArray(modifiedTbsDer));
        Extensions extensions = modifiedTbs.getExtensions();
        assertNotNull(extensions.getExtension(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier(CT_SCT_LIST_OID)),
                "SCT list extension must be present");
        assertNull(extensions.getExtension(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier(CT_POISON_OID)),
                "CT poison extension must be removed");
    }

    // -------------------------------------------------------------------------
    // SignedCertificateTimestamp record validation
    // -------------------------------------------------------------------------

    @Test
    void signedCertificateTimestamp_defensiveCopies() {
        byte[] logId = new byte[SignedCertificateTimestamp.LOG_ID_LENGTH];
        byte[] sig = new byte[]{0x01, 0x02};
        SignedCertificateTimestamp sct = new SignedCertificateTimestamp(
                0, logId, Instant.EPOCH, new byte[0], "SHA256withECDSA", sig);

        logId[0] = (byte) 0xFF;
        sig[0] = (byte) 0xFF;

        assertEquals(0, sct.logId()[0], "logId is defensively copied on construction");
        assertEquals(1, sct.signature()[0], "signature is defensively copied on construction");
        assertEquals(0, sct.logId()[0], "logId() accessor returns a fresh copy");
        assertEquals(1, sct.signature()[0], "signature() accessor returns a fresh copy");
    }

    @Test
    void signedCertificateTimestamp_shortLogId_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SignedCertificateTimestamp(0, new byte[16], Instant.EPOCH,
                        new byte[0], "SHA256withECDSA", new byte[]{0x01}));
    }

    @Test
    void signedCertificateTimestamp_emptySignature_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SignedCertificateTimestamp(0, new byte[32], Instant.EPOCH,
                        new byte[0], "SHA256withECDSA", new byte[0]));
    }
}
