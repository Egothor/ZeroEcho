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

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;

/** Exercises provider-neutral DER and strict fixed-suite signature contracts. */
class PkixEncodingTest {
    private static KeyPair p384() throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        return generator.generateKeyPair();
    }

    @Test
    void canonicalDerRejectsTrailingBytesAndUnwrapsOnlyOctetStrings() throws Exception {
        byte[] value = new DEROctetString(new byte[] {1, 2, 3}).getEncoded("DER");
        assertArrayEquals(value, PkixEncoding.canonicalDer(value));
        byte[] contents = PkixEncoding.octetStringContents(value);
        contents[0] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, PkixEncoding.octetStringContents(value));
        assertThrows(IOException.class, () -> PkixEncoding.canonicalDer(Arrays.copyOf(value, value.length + 1)));
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.octetStringContents(new byte[] {2, 1, 1}));
    }

    @Test
    void canonicalSubjectPublicKeyInfoRejectsPaddingAndNoncanonicalEncoding() throws Exception {
        byte[] key = p384().getPublic().getEncoded();
        assertDoesNotThrow(() -> PkixEncoding.requireCanonicalSubjectPublicKeyInfo(key));
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(key);
        byte[] padded = new DERSequence(new org.bouncycastle.asn1.ASN1Encodable[] {
                info.getAlgorithm(), new DERBitString(info.getPublicKeyData().getBytes(), 1)}).getEncoded("DER");
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireCanonicalSubjectPublicKeyInfo(padded));
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireCanonicalSubjectPublicKeyInfo(new byte[] {48, 0}));
    }

    @Test
    void p384SubjectPublicKeyRequiresNamedCurveAndFiniteValidUncompressedPoint() throws Exception {
        byte[] key = p384().getPublic().getEncoded();
        assertDoesNotThrow(() -> PkixEncoding.requireP384SubjectPublicKeyInfo(key));
        SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(key);
        byte[] absent = new SubjectPublicKeyInfo(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                info.getAlgorithm().getAlgorithm()), info.getPublicKeyData().getBytes()).getEncoded("DER");
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireP384SubjectPublicKeyInfo(absent));
        byte[] point = new byte[97]; point[0] = 4;
        byte[] offCurve = new SubjectPublicKeyInfo(info.getAlgorithm(), point).getEncoded("DER");
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireP384SubjectPublicKeyInfo(offCurve));
        byte[] infinity = new SubjectPublicKeyInfo(info.getAlgorithm(), new byte[] {0}).getEncoded("DER");
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireP384SubjectPublicKeyInfo(infinity));
    }

    @Test
    void p384SignatureEnforcesCanonicalScalarBounds() throws Exception {
        byte[] valid = PkixEncoding.ecdsaSignature(BigInteger.ONE, BigInteger.TWO);
        assertDoesNotThrow(() -> PkixEncoding.requireP384Signature(valid));
        BigInteger order = SECNamedCurves.getByName("secp384r1").getN();
        for (BigInteger invalid : new BigInteger[] {BigInteger.ZERO, BigInteger.ONE.negate(), order}) {
            byte[] value = PkixEncoding.ecdsaSignature(invalid, BigInteger.ONE);
            assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireP384Signature(value));
        }
        byte[] extra = new DERSequence(new ASN1Integer[] {new ASN1Integer(1), new ASN1Integer(2), new ASN1Integer(3)}).getEncoded("DER");
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireP384Signature(extra));
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireP384Signature(new byte[105]));
        assertThrows(IOException.class, () -> PkixEncoding.requireP384Signature(Arrays.copyOf(valid, valid.length + 1)));
    }

    @Test
    void canonicalCertificationRequestRejectsSignaturePaddingAndTrailingBytes() throws Exception {
        KeyPair key = p384();
        byte[] encoded = new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=encoding test"), key.getPublic())
                .build(new JcaContentSignerBuilder("SHA384withECDSA").setProvider("BC").build(key.getPrivate())).getEncoded();
        assertDoesNotThrow(() -> PkixEncoding.requireCanonicalCertificationRequest(encoded));
        CertificationRequest csr = CertificationRequest.getInstance(encoded);
        byte[] padded = new CertificationRequest(csr.getCertificationRequestInfo(), csr.getSignatureAlgorithm(),
                new DERBitString(csr.getSignature().getBytes(), 1)).getEncoded("DER");
        assertThrows(IllegalArgumentException.class, () -> PkixEncoding.requireCanonicalCertificationRequest(padded));
        assertThrows(IOException.class, () -> PkixEncoding.requireCanonicalCertificationRequest(Arrays.copyOf(encoded, encoded.length + 1)));
    }

    @Test
    void mldsaVerificationRequiresExplicitEmptyContextAndRejectsTampering() throws Exception {
        zeroecho.sdk.util.BouncyCastleActivator.init();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("ML-DSA", "BC");
        generator.initialize(new NamedParameterSpec("ML-DSA-87"));
        KeyPair key = generator.generateKeyPair();
        byte[] message = {1, 2, 3};
        Signature signer = Signature.getInstance("ML-DSA-87", "BC");
        signer.setParameter(new ContextParameterSpec(new byte[0]));
        signer.initSign(key.getPrivate()); signer.update(message); byte[] signature = signer.sign();
        assertTrue(PkixEncoding.verifyEmptyContextMldsa87(key.getPublic(), message, signature));
        assertFalse(PkixEncoding.verifyEmptyContextMldsa87(key.getPublic(), new byte[] {1, 2, 4}, signature));
        Signature contextualSigner = Signature.getInstance("ML-DSA-87", "BC");
        contextualSigner.setParameter(new ContextParameterSpec(new byte[] {1}));
        contextualSigner.initSign(key.getPrivate()); contextualSigner.update(message);
        assertFalse(PkixEncoding.verifyEmptyContextMldsa87(key.getPublic(), message, contextualSigner.sign()));
    }
}
