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
package zeroecho.pki.server.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.junit.jupiter.api.Test;

import zeroecho.pki.application.OcspResponseService;

/** Strict OCSP DER and GET request framing coverage. */
class OcspRequestParserTest {
    @Test
    void parsesCanonicalSha1Sha256AndExactNonce() throws Exception {
        System.out.println("parsesCanonicalSha1Sha256AndExactNonce");
        X509CertificateHolder issuer = certificate();
        DigestCalculator sha1 = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
        DigestCalculator sha256 = new JcaDigestCalculatorProviderBuilder().build().get(
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(sha1, issuer, BigInteger.valueOf(17)));
        builder.addRequest(new CertificateID(sha256, issuer, BigInteger.valueOf(18)));
        byte[] nonce = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
        builder.setRequestExtensions(new Extensions(new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce,
                false, new DEROctetString(new DEROctetString(nonce).getEncoded()))));
        byte[] encoded = builder.build().getEncoded();

        OcspRequestParser.Parsed parsed = OcspRequestParser.parse(encoded, 2,
                Set.of(OcspResponseService.CertIdHash.SHA1, OcspResponseService.CertIdHash.SHA256), 32);
        assertEquals(2, parsed.requests().size());
        assertEquals(OcspResponseService.CertIdHash.SHA1, parsed.requests().get(0).hash());
        assertEquals(OcspResponseService.CertIdHash.SHA256, parsed.requests().get(1).hash());
        assertArrayEquals(nonce, parsed.nonce().orElseThrow());
        String get = Base64.getUrlEncoder().withoutPadding().encodeToString(encoded);
        assertArrayEquals(encoded, OcspRequestParser.decodeGet(get, encoded.length));
        System.out.println("...entries=2 nonce=echoable");
        System.out.println("parsesCanonicalSha1Sha256AndExactNonce...ok");
    }

    @Test
    void acceptsSha256AbsentAndOpenSslNullParametersWithIdenticalCertId() throws Exception {
        X509CertificateHolder issuer = certificate();
        var digests = new JcaDigestCalculatorProviderBuilder().build();
        var absent = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
        var explicitNull = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256,
                org.bouncycastle.asn1.DERNull.INSTANCE);
        OCSPReqBuilder absentBuilder = new OCSPReqBuilder();
        absentBuilder.addRequest(new CertificateID(digests.get(absent), issuer, BigInteger.valueOf(19)));
        OCSPReqBuilder nullBuilder = new OCSPReqBuilder();
        nullBuilder.addRequest(new CertificateID(digests.get(explicitNull), issuer, BigInteger.valueOf(19)));
        var hashes = Set.of(OcspResponseService.CertIdHash.SHA256);
        var expected = OcspRequestParser.parse(absentBuilder.build().getEncoded(), 1, hashes, 32)
                .requests().getFirst();
        var actual = OcspRequestParser.parse(nullBuilder.build().getEncoded(), 1, hashes, 32)
                .requests().getFirst();
        assertEquals(expected.hash(), actual.hash());
        assertEquals(expected.serial(), actual.serial());
        assertArrayEquals(expected.issuerNameHash(), actual.issuerNameHash());
        assertArrayEquals(expected.issuerKeyHash(), actual.issuerKeyHash());
        assertThrows(IllegalArgumentException.class, () -> OcspRequestParser.parse(
                nullBuilder.build().getEncoded(), 1, Set.of(OcspResponseService.CertIdHash.SHA1), 32));
    }

    @Test
    void rejectsSha256NonNullParametersAndUnknownHashOid() throws Exception {
        for (AlgorithmIdentifier algorithm : java.util.List.of(
                new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256,
                        new org.bouncycastle.asn1.ASN1Integer(1)),
                new AlgorithmIdentifier(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4")))) {
            var certId = new org.bouncycastle.asn1.ocsp.CertID(algorithm,
                    new DEROctetString(new byte[32]), new DEROctetString(new byte[32]),
                    new org.bouncycastle.asn1.ASN1Integer(19));
            OCSPReqBuilder builder = new OCSPReqBuilder();
            builder.addRequest(new CertificateID(certId));
            byte[] encoded = builder.build().getEncoded();
            assertThrows(IllegalArgumentException.class, () -> OcspRequestParser.parse(encoded, 1,
                    Set.of(OcspResponseService.CertIdHash.SHA256), 32));
        }
    }

    @Test
    void rejectsAlternateGetEncodingBoundsAndUnknownCriticalExtension() throws Exception {
        System.out.println("rejectsAlternateGetEncodingBoundsAndUnknownCriticalExtension");
        X509CertificateHolder issuer = certificate();
        DigestCalculator digest = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(digest, issuer, BigInteger.ONE));
        builder.setRequestExtensions(new Extensions(new Extension(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.55555.1"), true,
                new DEROctetString(new byte[] { 5 }))));
        byte[] critical = builder.build().getEncoded();
        assertThrows(IllegalArgumentException.class, () -> OcspRequestParser.parse(critical, 1,
                Set.of(OcspResponseService.CertIdHash.SHA1), 32));
        assertThrows(IllegalArgumentException.class, () -> OcspRequestParser.parse(critical, 0,
                Set.of(OcspResponseService.CertIdHash.SHA1), 32));
        String canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(critical);
        assertThrows(IllegalArgumentException.class, () -> OcspRequestParser.decodeGet(canonical + "=", 4096));
        assertThrows(IllegalArgumentException.class, () -> OcspRequestParser.decodeGet(canonical, 1));
        assertThrows(IllegalArgumentException.class, () -> OcspRequestParser.parse(
                java.util.Arrays.copyOf(critical, critical.length + 1), 1,
                Set.of(OcspResponseService.CertIdHash.SHA1), 32));
        System.out.println("...strict-get-and-der=true");
        System.out.println("rejectsAlternateGetEncodingBoundsAndUnknownCriticalExtension...ok");
    }

    @Test
    void retainsExactSignedRequestAndRequiresExplicitSignerBounds() throws Exception {
        System.out.println("retainsExactSignedRequestAndRequiresExplicitSignerBounds");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keys = generator.generateKeyPair();
        X509CertificateHolder issuer = certificate(keys);
        DigestCalculator digest = new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1);
        OCSPReqBuilder builder = new OCSPReqBuilder();
        builder.addRequest(new CertificateID(digest, issuer, BigInteger.ONE));
        builder.setRequestorName(new GeneralName(issuer.getSubject()));
        byte[] signed = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate()),
                new X509CertificateHolder[] { issuer }).getEncoded();
        assertThrows(IllegalArgumentException.class, () -> OcspRequestParser.parse(signed, 1,
                Set.of(OcspResponseService.CertIdHash.SHA1), 32));
        OcspRequestParser.Parsed parsed = OcspRequestParser.parse(signed, 1,
                Set.of(OcspResponseService.CertIdHash.SHA1), 32, 2, 32_768);
        assertTrue(parsed.signedRequest().isPresent());
        assertArrayEquals(issuer.getSubject().getEncoded(),
                parsed.signedRequest().orElseThrow().requestorName());
        assertArrayEquals(issuer.getEncoded(),
                parsed.signedRequest().orElseThrow().certificates().getFirst());
        assertTrue(parsed.signedRequest().orElseThrow().tbsRequest().length > 0);
        System.out.println("...exact-tbs-and-certificate-retained=true");
        System.out.println("retainsExactSignedRequestAndRequiresExplicitSignerBounds...ok");
    }

    private static X509CertificateHolder certificate() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return certificate(generator.generateKeyPair());
    }

    private static X509CertificateHolder certificate(KeyPair keys) throws Exception {
        X500Name name = new X500Name("CN=OCSP Parser Issuer");
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(name, BigInteger.ONE,
                Date.from(Instant.parse("2025-01-01T00:00:00Z")),
                Date.from(Instant.parse("2030-01-01T00:00:00Z")), name,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded()));
        return builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keys.getPrivate()));
    }
}
