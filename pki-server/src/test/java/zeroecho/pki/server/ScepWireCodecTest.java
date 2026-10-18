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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import zeroecho.pkix.AlgorithmIdentifier;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.scep.ScepCodec;
import zeroecho.pkix.scep.ScepCodecException;

class ScepWireCodecTest {
    private static KeyPair requester;
    private static KeyPair ra;
    private static X509Certificate requesterCertificate;
    private static X509Certificate raCertificate;
    private static final byte[] NONCE = new byte[16];

    @BeforeAll static void keys() throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG"); random.setSeed(new byte[] {91, 13, 6});
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048, random);
        requester = generator.generateKeyPair(); ra = generator.generateKeyPair();
        requesterCertificate = certificate(requester, "Requester", 1);
        raCertificate = certificate(ra, "RA", 2);
    }

    private static X509Certificate certificate(KeyPair pair, String commonName, int serial) throws Exception {
        X500Principal name = new X500Principal("CN=" + commonName);
        return Pkix.certificateBuilder().subject(name).issuer(name).publicKey(pair.getPublic())
                .serialNumber(java.math.BigInteger.valueOf(serial))
                .validity(Instant.parse("2026-01-01T00:00:00Z"), Instant.parse("2028-01-01T00:00:00Z"))
                .keyUsage(Set.of(zeroecho.pkix.KeyUsage.DIGITAL_SIGNATURE, zeroecho.pkix.KeyUsage.KEY_ENCIPHERMENT), true)
                .build(Pkix.signer(pair.getPrivate(), AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11")));
    }

    @Test void independentEnvelopeVerifiesBeforeExactRecipientDecryption() throws Exception {
        byte[] csr = ScepTestClient.csr(requester, "scep-test-challenge");
        byte[] encoded = ScepTestClient.request(csr, "transaction-one", NONCE, 19, requester, requesterCertificate, raCertificate);
        ScepCodec.VerifiedRequest verified = ScepCodec.verifyRequest(encoded);
        assertEquals("transaction-one", verified.transactionId());
        assertEquals(requesterCertificate, verified.requesterCertificate());
        assertArrayEquals(csr, ScepCodec.decryptRequest(verified, raCertificate, ra.getPrivate()).innerContent());
        assertThrows(ScepCodecException.class, () -> ScepCodec.decryptRequest(verified, requesterCertificate, requester.getPrivate()));
        byte[] nonceCopy = verified.senderNonce(); nonceCopy[0] = 1; assertArrayEquals(NONCE, verified.senderNonce());
        assertEquals("scep-test-challenge", ScepCodec.extractChallengePassword(csr));
    }

    @Test void rejectsUnverifiedSignerAttributesAlgorithmsAndBounds() throws Exception {
        byte[] csr = ScepTestClient.csr(requester, "challenge");
        for (String variant : java.util.List.of("badSignature", "duplicateSigner", "duplicateAttribute", "wrongType", "sha1", "wrongOuterType")) {
            byte[] wire = ScepTestClient.request(csr, "transaction", NONCE, 19, requester, requesterCertificate, raCertificate, variant);
            assertThrows(ScepCodecException.class, () -> ScepCodec.verifyRequest(wire), variant);
        }
        assertThrows(ScepCodecException.class, () -> ScepCodec.verifyRequest(
                ScepTestClient.request(csr, "transaction", new byte[15], 19, requester, requesterCertificate, raCertificate)));
        assertThrows(ScepCodecException.class, () -> ScepCodec.verifyRequest(
                ScepTestClient.request(csr, "transaction", NONCE, 19, ra, requesterCertificate, raCertificate)));
        assertThrows(ScepCodecException.class, () -> ScepCodec.verifyRequest(new byte[ScepCodec.MAXIMUM_REQUEST_BYTES + 1]));
        for (String variant : java.util.List.of("duplicateRecipient", "aes256", "wrongInnerType", "wrongEncryptedType", "trailingInner")) {
            ScepCodec.VerifiedRequest wire = ScepCodec.verifyRequest(ScepTestClient.request(csr, "transaction", NONCE, 19,
                    requester, requesterCertificate, raCertificate, variant));
            assertThrows(ScepCodecException.class, () -> ScepCodec.decryptRequest(wire, raCertificate, ra.getPrivate()), variant);
        }
    }

    @Test void challengeDirectoryStringUsesActualUnicodeScalarsAcrossEncodings() throws Exception {
        String oid = "1.2.840.113549.1.9.7";
        String expected = "challenge";
        for (org.bouncycastle.asn1.ASN1Encodable encoded : java.util.List.of(
                new org.bouncycastle.asn1.DERUTF8String(expected), new org.bouncycastle.asn1.DERPrintableString(expected),
                new org.bouncycastle.asn1.DERBMPString(expected), new org.bouncycastle.asn1.DERUniversalString(
                        expected.getBytes(java.nio.charset.Charset.forName("UTF-32BE"))))) {
            assertEquals(expected, new zeroecho.pkix.csr.CsrAttribute(oid, java.util.List.of(encoded.toASN1Primitive().getEncoded())).challengePassword());
        }
        String supplementary = "challenge\uD83D\uDD11";
        assertEquals(supplementary, new zeroecho.pkix.csr.CsrAttribute(oid, java.util.List.of(new org.bouncycastle.asn1.DERUniversalString(
                supplementary.getBytes(java.nio.charset.Charset.forName("UTF-32BE"))).getEncoded())).challengePassword());
        for (byte[] invalid : java.util.List.of(new byte[] {0, 0, (byte) 0xD8, 0}, new byte[] {0, 0x11, 0, 0}, new byte[] {0})) {
            assertThrows(IllegalArgumentException.class, () -> new zeroecho.pkix.csr.CsrAttribute(oid,
                    java.util.List.of(new org.bouncycastle.asn1.DERUniversalString(invalid).getEncoded())).challengePassword());
        }
        assertThrows(IllegalArgumentException.class, () -> new zeroecho.pkix.csr.CsrAttribute(oid,
                java.util.List.of(new org.bouncycastle.asn1.DERBMPString("\uD800").getEncoded())).challengePassword());
    }

    @Test void pendingFailureAndSuccessAreIndependentlyVerified() throws Exception {
        assertEquals("3", ScepTestClient.response(ScepCodec.buildCertRepPending("transaction", NONCE, raCertificate, ra.getPrivate()),
                raCertificate, requester, NONCE).status());
        assertEquals("2", ScepTestClient.response(ScepCodec.buildCertRepFailure("transaction", NONCE, "2", raCertificate, ra.getPrivate()),
                raCertificate, requester, NONCE).status());
        assertEquals(requesterCertificate, ScepTestClient.response(ScepCodec.buildCertRepSuccess("transaction", NONCE,
                requesterCertificate.getEncoded(), requesterCertificate, raCertificate, ra.getPrivate()), raCertificate, requester, NONCE).certificate());
    }
}
