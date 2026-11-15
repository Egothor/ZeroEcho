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
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.pkix.cert.CertificateBuilder;

/** Independent ASN.1 transcript assertions and real signatures for the Cor.3 baseline. */
final class Cor3AlternativeSignatureTest {
    private static final AlgorithmIdentifier NATIVE = AlgorithmIdentifier.absent("1.2.840.10045.4.3.3");
    private static final AlgorithmIdentifier ALT = AlgorithmIdentifier.absent("2.16.840.1.101.3.4.3.19");
    @BeforeAll static void providers() { zeroecho.sdk.util.BouncyCastleActivator.init(); }

    @Test void retainsBothNativeAlgorithmsAndRejectsLegacyTranscriptAndTampering() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC", "BC");
        generator.initialize(new ECGenParameterSpec("secp384r1"));
        KeyPair primary = generator.generateKeyPair();
        KeyPair alternative = KeyPairGenerator.getInstance("ML-DSA-87", "BC").generateKeyPair();
        byte[] input = builder(primary, alternative).buildAlternativeSignatureTbs(NATIVE);
        ASN1Sequence transcript = ASN1Sequence.getInstance(input);
        assertEquals(2, transcript.size());
        TBSCertificate tbs = TBSCertificate.getInstance(transcript.getObjectAt(0));
        assertArrayEquals(Pkix.encodeAlgorithmIdentifier(NATIVE), tbs.getSignature().getEncoded("DER"));
        assertArrayEquals(Pkix.encodeAlgorithmIdentifier(NATIVE), transcript.getObjectAt(1).toASN1Primitive().getEncoded("DER"));
        assertNotNull(tbs.getExtensions().getExtension(Extension.subjectAltPublicKeyInfo));
        assertNotNull(tbs.getExtensions().getExtension(Extension.altSignatureAlgorithm));
        assertNull(tbs.getExtensions().getExtension(Extension.altSignatureValue));
        Signature signer = Signature.getInstance("ML-DSA-87", "BC");
        signer.initSign(alternative.getPrivate()); signer.update(input); byte[] signature = signer.sign();
        var certificate = builder(primary, alternative).addExtension(value(signature))
                .build(Pkix.signer(primary.getPrivate(), NATIVE));
        certificate.verify(primary.getPublic(), "BC");
        assertTrue(Pkix.verifyAlternativeSignatureCor3(certificate, alternative.getPublic()));
        assertFalse(Pkix.verifyAlternativeSignature(certificate, alternative.getPublic()));
        assertFalse(Pkix.verifyAlternativeSignatureCor3(certificate,
                KeyPairGenerator.getInstance("ML-DSA-87", "BC").generateKeyPair().getPublic()));
        signature[0] ^= 1;
        var tampered = builder(primary, alternative).addExtension(value(signature))
                .build(Pkix.signer(primary.getPrivate(), NATIVE));
        tampered.verify(primary.getPublic(), "BC");
        assertFalse(Pkix.verifyAlternativeSignatureCor3(tampered, alternative.getPublic()));
        var missing = builder(primary, alternative).build(Pkix.signer(primary.getPrivate(), NATIVE));
        assertFalse(Pkix.verifyAlternativeSignatureCor3(missing, alternative.getPublic()));
    }

    @Test void excludesExistingAlternativeValueRegardlessOfItsBytes() throws Exception {
        KeyPair primary = KeyPairGenerator.getInstance("Ed25519", "BC").generateKeyPair();
        KeyPair alternative = KeyPairGenerator.getInstance("ML-DSA-87", "BC").generateKeyPair();
        byte[] expected = builder(primary, alternative).buildAlternativeSignatureTbs(NATIVE);
        assertArrayEquals(expected, builder(primary, alternative).addExtension(value(new byte[4627]))
                .buildAlternativeSignatureTbs(NATIVE));
        assertThrows(NullPointerException.class, () -> builder(primary, alternative).buildAlternativeSignatureTbs(null));
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.CsvSource({
            "root,08e5b9e128853cdeeb401149cc03ca887b14a0c2469fc602d5b7884ce58fca3d",
            "intermediate,34d18352840efc28c3685e3d46d8749d0f56663d5ecdbc26945083def0aa084d"})
    void matchesIndependentSyntheticStructuralVector(String name, String expectedSha256) throws Exception {
        // These independently supplied DER fixtures contain synthetic public bits.
        // They test the exact transform and make no claim of cryptographic validity.
        byte[] expected;
        try (var resource = getClass().getResourceAsStream("/zeroecho/pkix/cor3/" + name + "-unsigned.der")) {
            expected = java.util.Objects.requireNonNull(resource).readAllBytes();
        }
        assertEquals(expectedSha256, java.util.HexFormat.of().formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(expected)));
        var sequence = ASN1Sequence.getInstance(expected);
        var tbs = TBSCertificate.getInstance(sequence.getObjectAt(0));
        var builder = Pkix.certificateBuilder().serialNumber(tbs.getSerialNumber().getValue())
                .issuer(new X500Principal(tbs.getIssuer().getEncoded("DER")))
                .subject(new X500Principal(tbs.getSubject().getEncoded("DER")))
                .validity(tbs.getStartDate().getDate().toInstant(), tbs.getEndDate().getDate().toInstant())
                .publicKeyInfo(tbs.getSubjectPublicKeyInfo().getEncoded("DER"));
        for (var oid : tbs.getExtensions().getExtensionOIDs()) {
            var extension = tbs.getExtensions().getExtension(oid);
            builder.addExtension(new CertificateExtension(oid.getId(), extension.isCritical(), extension.getExtnValue().getOctets()));
        }
        builder.addExtension(value(new byte[4627]));
        assertArrayEquals(expected, builder.buildAlternativeSignatureTbs(NATIVE));
    }

    private static CertificateBuilder builder(KeyPair primary, KeyPair alternative) {
        Instant start = Instant.parse("2026-11-01T00:00:00Z");
        return Pkix.certificateBuilder().serialNumber(BigInteger.ONE)
                .issuer(new X500Principal("CN=Cor3 issuer")).subject(new X500Principal("CN=Cor3 subject"))
                .validity(start, start.plusSeconds(3600)).publicKey(primary.getPublic())
                .addExtension(new CertificateExtension("2.5.29.72", false, alternative.getPublic().getEncoded()))
                .addExtension(new CertificateExtension("2.5.29.73", false, Pkix.encodeAlgorithmIdentifier(ALT)));
    }
    private static CertificateExtension value(byte[] signature) throws Exception {
        return new CertificateExtension("2.5.29.74", false, new DERBitString(signature).getEncoded("DER"));
    }
}
