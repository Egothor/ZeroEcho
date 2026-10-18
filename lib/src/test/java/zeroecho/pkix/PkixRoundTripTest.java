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
package zeroecho.pkix;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.EnumSet;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;

import zeroecho.pkix.crl.CrlEntry;
import zeroecho.pkix.crl.CrlReason;
import zeroecho.pkix.csr.CertificationRequest;
import zeroecho.pkix.ocsp.CertId;
import zeroecho.pkix.ocsp.CertStatus;
import zeroecho.pkix.ocsp.OcspRequest;
import zeroecho.pkix.ocsp.ResponderId;
import zeroecho.pkix.sign.ContentSigner;

/** End-to-end round trips of the JCA-aligned PKIX API over the BouncyCastle backend. */
class PkixRoundTripTest {

    private static final AlgorithmIdentifier SHA256_RSA =
            AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");
    private static final String SHA1_OID = "1.3.14.3.2.26";

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static ContentSigner signer(KeyPair issuer) {
        return Pkix.signer(issuer.getPrivate(), SHA256_RSA);
    }

    @Test
    void certificateBuildsParsesAndVerifies() throws Exception {
        KeyPair ca = rsa();
        X500Principal name = new X500Principal("CN=Example Root CA");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate cert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE)
                .subject(name)
                .issuer(name)
                .validity(now, now.plus(365, ChronoUnit.DAYS))
                .publicKey(ca.getPublic())
                .basicConstraints(BasicConstraints.ca(1), true)
                .keyUsage(EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), true)
                .subjectKeyIdentifier()
                .build(signer(ca));

        X509Certificate parsed = Pkix.parseCertificate(cert.getEncoded());
        parsed.verify(ca.getPublic());
        assertEquals(name, parsed.getSubjectX500Principal());
        assertEquals(1, parsed.getBasicConstraints());
        assertTrue(parsed.getKeyUsage()[5], "keyCertSign");
        assertNotNull(parsed.getExtensionValue("2.5.29.14"), "subjectKeyIdentifier present");
    }

    @Test
    void certificationRequestBuildsParsesAndVerifies() throws Exception {
        KeyPair leaf = rsa();
        X500Principal subject = new X500Principal("CN=leaf.example.com");
        CertificationRequest csr = Pkix.certificationRequestBuilder()
                .subject(subject)
                .publicKey(leaf.getPublic())
                .subjectAlternativeNames(List.of(new GeneralName.DnsName("leaf.example.com")), false)
                .build(signer(leaf));

        CertificationRequest parsed = Pkix.parseCertificationRequest(csr.encoded());
        assertTrue(parsed.verifySelfSignature(), "proof of possession");
        assertEquals(subject, parsed.subject());
        assertEquals(leaf.getPublic(), parsed.publicKey());
        assertTrue(parsed.requestedSubjectAlternativeNames()
                .contains(new GeneralName.DnsName("leaf.example.com")));
    }

    @Test
    void crlBuildsAndParses() throws Exception {
        KeyPair ca = rsa();
        X500Principal name = new X500Principal("CN=Example Root CA");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509CRL crl = Pkix.crlBuilder()
                .issuer(name)
                .thisUpdate(now)
                .nextUpdate(now.plus(7, ChronoUnit.DAYS))
                .crlNumber(BigInteger.ONE)
                .addEntry(new CrlEntry(BigInteger.TWO, now, CrlReason.KEY_COMPROMISE))
                .build(signer(ca));

        X509CRL parsed = Pkix.parseCrl(crl.getEncoded());
        parsed.verify(ca.getPublic());
        assertEquals(name, parsed.getIssuerX500Principal());
        assertNotNull(parsed.getRevokedCertificate(BigInteger.TWO), "revoked entry present");
    }

    @Test
    void ocspResponseBuildsAsSuccessful() throws Exception {
        KeyPair ca = rsa();
        X500Principal name = new X500Principal("CN=Example Root CA");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate caCert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE).subject(name).issuer(name)
                .validity(now, now.plus(365, ChronoUnit.DAYS)).publicKey(ca.getPublic())
                .basicConstraints(BasicConstraints.ca(), true)
                .keyUsage(EnumSet.of(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN), true)
                .build(signer(ca));

        CertId certId = Pkix.computeCertId(caCert, BigInteger.TEN, SHA1_OID);
        byte[] response = Pkix.ocspResponseBuilder()
                .responderId(ResponderId.byName(name))
                .producedAt(now)
                .addResponse(certId, CertStatus.good(), now, now.plus(1, ChronoUnit.DAYS))
                .build(signer(ca), List.of(caCert));

        assertTrue(response.length > 0);
        org.bouncycastle.cert.ocsp.OCSPResp parsed = new org.bouncycastle.cert.ocsp.OCSPResp(response);
        assertEquals(org.bouncycastle.cert.ocsp.OCSPResp.SUCCESSFUL, parsed.getStatus());
    }

    @Test
    void distinguishedNameIsByteExactAndRawSpkiBuildsCerts() throws Exception {
        KeyPair ca = rsa();
        X500Principal built = Pkix.distinguishedName(List.of(
                new RelativeDistinguishedName("2.5.4.6", "US", DirectoryStringType.PRINTABLE),
                new RelativeDistinguishedName("2.5.4.3", "Example Root CA", DirectoryStringType.UTF8)));
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        byte[] spki = ca.getPublic().getEncoded();
        X509Certificate cert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE).subject(built).issuer(built)
                .validity(now, now.plus(365, ChronoUnit.DAYS))
                .publicKeyInfo(spki)
                .basicConstraints(BasicConstraints.ca(), true)
                .build(signer(ca));

        X509Certificate parsed = Pkix.parseCertificate(cert.getEncoded());
        // Byte-exact DN round trip through the certificate.
        assertEquals(built, parsed.getSubjectX500Principal());
        // Raw SPKI preserved exactly.
        assertEquals(java.util.HexFormat.of().formatHex(spki),
                java.util.HexFormat.of().formatHex(parsed.getPublicKey().getEncoded()));
        // SPKI helpers.
        assertEquals("1.2.840.113549.1.1.1", Pkix.subjectPublicKeyAlgorithm(spki).oid());
        assertEquals(ca.getPublic(), Pkix.publicKeyFromSubjectPublicKeyInfo(spki));
    }

    @Test
    void parsesTypedDistinguishedNameAndSpkiHelpers() throws Exception {
        KeyPair ca = rsa();
        List<RelativeDistinguishedName> rdns = List.of(
                new RelativeDistinguishedName("2.5.4.6", "US", DirectoryStringType.PRINTABLE),
                new RelativeDistinguishedName("2.5.4.3", "Example Leaf", DirectoryStringType.UTF8));
        X500Principal built = Pkix.distinguishedName(rdns);
        assertEquals(rdns, Pkix.parseDistinguishedName(built.getEncoded()));

        byte[] spki = ca.getPublic().getEncoded();
        // The public-key bit-string bytes are a prefix-free suffix of the SPKI DER.
        assertNotNull(Pkix.subjectPublicKeyBytes(spki));
        assertTrue(Pkix.subjectPublicKeyBytes(spki).length > 0);

        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate cert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE).subject(built).issuer(built)
                .validity(now, now.plus(365, ChronoUnit.DAYS)).publicKeyInfo(spki)
                .build(signer(ca));
        assertEquals(java.util.HexFormat.of().formatHex(spki),
                java.util.HexFormat.of().formatHex(Pkix.subjectPublicKeyInfo(cert)));
    }

    @Test
    void ocspResponseParsesAndVerifies() throws Exception {
        KeyPair ca = rsa();
        X500Principal name = new X500Principal("CN=Example Root CA");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate caCert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE).subject(name).issuer(name)
                .validity(now, now.plus(365, ChronoUnit.DAYS)).publicKey(ca.getPublic())
                .basicConstraints(BasicConstraints.ca(), true).build(signer(ca));
        CertId certId = Pkix.computeCertId(caCert, BigInteger.TEN, SHA1_OID);
        byte[] der = Pkix.ocspResponseBuilder().responderId(ResponderId.byName(name)).producedAt(now)
                .addResponse(certId, CertStatus.good(), now, now.plus(1, ChronoUnit.DAYS))
                .build(signer(ca), List.of(caCert));

        zeroecho.pkix.ocsp.OcspResponse parsed = Pkix.parseOcspResponse(der);
        assertTrue(parsed.isSuccessful());
        assertTrue(parsed.verifySignature(ca.getPublic()));
        assertEquals(1, parsed.responses().size());
        assertTrue(parsed.responses().get(0).status() instanceof CertStatus.Good);
    }

    @Test
    void ocspRequestParses() throws Exception {
        KeyPair ca = rsa();
        X500Principal name = new X500Principal("CN=Example Root CA");
        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        X509Certificate caCert = Pkix.certificateBuilder()
                .serialNumber(BigInteger.ONE).subject(name).issuer(name)
                .validity(now, now.plus(365, ChronoUnit.DAYS)).publicKey(ca.getPublic())
                .basicConstraints(BasicConstraints.ca(), true).build(signer(ca));

        org.bouncycastle.operator.DigestCalculator digest =
                new org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder().build()
                        .get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                new org.bouncycastle.asn1.ASN1ObjectIdentifier(SHA1_OID)));
        org.bouncycastle.cert.ocsp.OCSPReqBuilder builder =
                new org.bouncycastle.cert.ocsp.OCSPReqBuilder();
        builder.addRequest(new org.bouncycastle.cert.ocsp.CertificateID(digest,
                new org.bouncycastle.cert.X509CertificateHolder(caCert.getEncoded()), BigInteger.TEN));
        byte[] der = builder.build().getEncoded();

        OcspRequest parsed = Pkix.parseOcspRequest(der);
        assertEquals(1, parsed.requestedCertificates().size());
        assertEquals(BigInteger.TEN, parsed.requestedCertificates().get(0).serialNumber());
    }
}
