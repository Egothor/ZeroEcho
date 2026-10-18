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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.junit.jupiter.api.Test;
import zeroecho.sdk.util.BouncyCastleActivator;

class PublicKeyIdentityTest {
    @Test
    void rsaAbsentAndNullParametersAcrossProvidersHaveOneIdentity() throws Exception {
        BouncyCastleActivator.init();
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        random.setSeed(new byte[] { 33, 19, 81 });
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "SunRsaSign");
        generator.initialize(2048, random);
        KeyPair key = generator.generateKeyPair();
        SubjectPublicKeyInfo original = SubjectPublicKeyInfo.getInstance(key.getPublic().getEncoded());
        byte[] absent = new SubjectPublicKeyInfo(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                PKCSObjectIdentifiers.rsaEncryption), original.parsePublicKey()).getEncoded(ASN1Encoding.DER);
        PublicKeyIdentity identity = PublicKeyIdentity.fromSubjectPublicKeyInfo(original.getEncoded(ASN1Encoding.DER));
        assertEquals(identity.canonicalSha256(), PublicKeyIdentity.fromSubjectPublicKeyInfo(absent).canonicalSha256());
        assertEquals(identity.canonicalSha256(), PublicKeyIdentity.fromSubjectPublicKeyInfo(
                KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(absent)).getEncoded()).canonicalSha256());
        assertTrue(identity.equivalentSubjectPublicKeyInfoSha256().contains(digest(absent)));
        assertTrue(identity.equivalentSubjectPublicKeyInfoSha256().contains(digest(key.getPublic().getEncoded())));
        assertEquals(2, identity.equivalentSubjectPublicKeyInfoSha256().size());
        byte[] exposed = identity.canonicalSubjectPublicKeyInfo();
        exposed[0] ^= 1;
        assertArrayEquals(original.getEncoded(ASN1Encoding.DER), identity.canonicalSubjectPublicKeyInfo());
        assertThrows(UnsupportedOperationException.class, () -> identity.equivalentSubjectPublicKeyInfoSha256().clear());
        assertEquals("PublicKeyIdentity[redacted]", identity.toString());
    }

    @Test
    void allSupportedNamedCurvesNormalizeCompressedPointsAcrossProviders() throws Exception {
        BouncyCastleActivator.init();
        for (org.bouncycastle.asn1.ASN1ObjectIdentifier curve : List.of(SECObjectIdentifiers.secp256r1,
                SECObjectIdentifiers.secp384r1, SECObjectIdentifiers.secp521r1)) {
            X9ECParameters parameters = SECNamedCurves.getByOID(curve);
            org.bouncycastle.math.ec.ECPoint point = parameters.getG().multiply(BigInteger.valueOf(7));
            org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm =
                    new org.bouncycastle.asn1.x509.AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, curve);
            byte[] uncompressed = new SubjectPublicKeyInfo(algorithm, point.getEncoded(false)).getEncoded(ASN1Encoding.DER);
            byte[] compressed = new SubjectPublicKeyInfo(algorithm, point.getEncoded(true)).getEncoded(ASN1Encoding.DER);
            PublicKeyIdentity identity = PublicKeyIdentity.fromSubjectPublicKeyInfo(uncompressed);
            assertEquals(identity.canonicalSha256(), PublicKeyIdentity.fromSubjectPublicKeyInfo(compressed).canonicalSha256());
            assertEquals(identity.canonicalSha256(), PublicKeyIdentity.fromSubjectPublicKeyInfo(
                    KeyFactory.getInstance("EC", "BC").generatePublic(new X509EncodedKeySpec(compressed)).getEncoded()).canonicalSha256());
            assertEquals(identity.canonicalSha256(), PublicKeyIdentity.fromSubjectPublicKeyInfo(
                    KeyFactory.getInstance("EC", "SunEC").generatePublic(new X509EncodedKeySpec(uncompressed)).getEncoded()).canonicalSha256());
            assertEquals(java.util.Set.of(digest(compressed), digest(uncompressed)), identity.equivalentSubjectPublicKeyInfoSha256());
            byte[] different = new SubjectPublicKeyInfo(algorithm, parameters.getG().multiply(BigInteger.valueOf(8))
                    .getEncoded(false)).getEncoded(ASN1Encoding.DER);
            assertNotEquals(identity.canonicalSha256(), PublicKeyIdentity.fromSubjectPublicKeyInfo(different).canonicalSha256());
        }
    }

    @Test
    void rejectsUnsupportedAlgorithmsParametersInvalidPointsAndMalformedEncodings() throws Exception {
        RSAPublicKey valid = new RSAPublicKey(BigInteger.valueOf(3233), BigInteger.valueOf(17));
        for (org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm : List.of(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS),
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption,
                        new org.bouncycastle.asn1.ASN1Integer(1)),
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.101.112")))) {
            byte[] bytes = new SubjectPublicKeyInfo(algorithm, valid).getEncoded(ASN1Encoding.DER);
            assertThrows(IllegalArgumentException.class, () -> PublicKeyIdentity.fromSubjectPublicKeyInfo(bytes));
        }
        org.bouncycastle.asn1.x509.AlgorithmIdentifier rsa =
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
        for (RSAPublicKey key : List.of(new RSAPublicKey(BigInteger.valueOf(4), BigInteger.valueOf(3)),
                new RSAPublicKey(BigInteger.valueOf(3233), BigInteger.ONE),
                new RSAPublicKey(BigInteger.valueOf(3233), BigInteger.valueOf(3233)))) {
            byte[] bytes = new SubjectPublicKeyInfo(rsa, key).getEncoded(ASN1Encoding.DER);
            assertThrows(IllegalArgumentException.class, () -> PublicKeyIdentity.fromSubjectPublicKeyInfo(bytes));
        }
        X9ECParameters parameters = SECNamedCurves.getByOID(SECObjectIdentifiers.secp256r1);
        byte[] point = parameters.getG().getEncoded(false);
        for (org.bouncycastle.asn1.x509.AlgorithmIdentifier algorithm : List.of(
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, parameters),
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, DERNull.INSTANCE),
                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256k1))) {
            byte[] bytes = new SubjectPublicKeyInfo(algorithm, point).getEncoded(ASN1Encoding.DER);
            assertThrows(IllegalArgumentException.class, () -> PublicKeyIdentity.fromSubjectPublicKeyInfo(bytes));
        }
        org.bouncycastle.asn1.x509.AlgorithmIdentifier ec = new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey, SECObjectIdentifiers.secp256r1);
        byte[] hybrid = point.clone(); hybrid[0] = 6;
        byte[] offCurve = point.clone(); offCurve[20] ^= 1;
        for (byte[] invalid : List.of(new byte[] { 0 }, hybrid, offCurve, Arrays.copyOf(point, point.length - 1),
                Arrays.copyOf(point, point.length + 1), new org.bouncycastle.asn1.DEROctetString(point).getEncoded())) {
            byte[] bytes = new SubjectPublicKeyInfo(ec, invalid).getEncoded(ASN1Encoding.DER);
            assertThrows(IllegalArgumentException.class, () -> PublicKeyIdentity.fromSubjectPublicKeyInfo(bytes));
        }
        byte[] original = new SubjectPublicKeyInfo(rsa, valid).getEncoded(ASN1Encoding.DER);
        for (byte[] invalid : List.of(Arrays.copyOf(original, original.length - 1), Arrays.copyOf(original, original.length + 1),
                new byte[PublicKeyIdentity.MAXIMUM_SPKI_BYTES + 1], new byte[0])) {
            assertThrows(IllegalArgumentException.class, () -> PublicKeyIdentity.fromSubjectPublicKeyInfo(invalid));
        }
    }

    private static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
