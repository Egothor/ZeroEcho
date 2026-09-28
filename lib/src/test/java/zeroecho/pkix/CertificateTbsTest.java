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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.junit.jupiter.api.Test;

import zeroecho.pkix.cert.CertificateBuilder;

final class CertificateTbsTest {
    private static final AlgorithmIdentifier SIGNATURE = AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");

    @Test
    void unsignedCanonicalTbsEqualsTheExistingSignedBuilderOutput() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair key = generator.generateKeyPair();
        byte[] spki = key.getPublic().getEncoded();
        CertificateBuilder unsigned = builder(spki);
        spki[0] ^= 1;
        byte[] tbs = unsigned.buildTbs(SIGNATURE);
        TBSCertificate decoded = TBSCertificate.getInstance(tbs);
        assertArrayEquals(tbs, decoded.getEncoded(ASN1Encoding.DER));
        assertEquals(SIGNATURE.oid(), decoded.getSignature().getAlgorithm().getId());
        assertArrayEquals(key.getPublic().getEncoded(), decoded.getSubjectPublicKeyInfo().getEncoded(ASN1Encoding.DER));
        assertArrayEquals(builder(key.getPublic().getEncoded()).build(Pkix.signer(key.getPrivate(), SIGNATURE))
                .getTBSCertificate(), tbs);
    }

    @Test
    void rejectsMissingFieldsWithoutAnySigner() {
        assertThrows(NullPointerException.class, () -> Pkix.certificateBuilder().buildTbs(SIGNATURE));
        assertThrows(NullPointerException.class, () -> Pkix.certificateBuilder().buildTbs(null));
        assertThrows(IllegalArgumentException.class, () -> builder(new byte[0])
                .serialNumber(BigInteger.ZERO).buildTbs(SIGNATURE));
        assertThrows(IllegalArgumentException.class, () -> builder(new byte[0])
                .validity(Instant.EPOCH, Instant.EPOCH).buildTbs(SIGNATURE));
    }

    private static CertificateBuilder builder(byte[] spki) {
        return Pkix.certificateBuilder().serialNumber(BigInteger.valueOf(37))
                .issuer(new X500Principal("CN=Issuer")).subject(new X500Principal("CN=Leaf"))
                .validity(Instant.parse("2026-09-20T00:00:00Z"), Instant.parse("2027-09-20T00:00:00Z"))
                .publicKeyInfo(spki).basicConstraints(BasicConstraints.endEntity(), true)
                .keyUsage(Set.of(KeyUsage.DIGITAL_SIGNATURE), true)
                .extendedKeyUsage(ExtendedKeyUsage.of(ExtendedKeyUsage.SERVER_AUTH), false)
                .subjectAlternativeNames(List.of(new GeneralName.DnsName("leaf.example.test")), false)
                .subjectKeyIdentifier().authorityKeyIdentifier(new byte[] { 1, 2, 3 });
    }
}
