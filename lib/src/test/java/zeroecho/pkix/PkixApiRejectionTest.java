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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.Test;

import zeroecho.pkix.csr.CertificationRequest;

/**
 * Negative/rejection coverage for the {@code zeroecho.pkix} API: malformed inputs
 * are rejected, and a certification request whose embedded key does not match the
 * signing key fails proof-of-possession. Complements the positive round trips in
 * {@link PkixRoundTripTest} (PKIX conformance).
 */
class PkixApiRejectionTest {

    private static final AlgorithmIdentifier SHA256_RSA =
            AlgorithmIdentifier.derNull("1.2.840.113549.1.1.11");
    private static final byte[] GARBAGE = { 0x30, 0x03, 0x02, 0x01, 0x7f, (byte) 0xde, (byte) 0xad };
    private static final byte[] NOT_DER = "this is not DER".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    @Test
    void rejectsMalformedCertificateCsrCrlOcspAndBadPoP() throws Exception {
        // Malformed DER is rejected by every parser.
        assertThrows(RuntimeException.class, () -> Pkix.parseCertificate(GARBAGE));
        assertThrows(RuntimeException.class, () -> Pkix.parseCertificate(NOT_DER));
        assertThrows(RuntimeException.class, () -> Pkix.parseCrl(GARBAGE));
        assertThrows(RuntimeException.class, () -> Pkix.parseCertificationRequest(GARBAGE));
        assertThrows(RuntimeException.class, () -> Pkix.parseOcspRequest(GARBAGE));
        assertThrows(RuntimeException.class, () -> Pkix.parseOcspResponse(GARBAGE));
        assertThrows(RuntimeException.class, () -> Pkix.subjectPublicKeyAlgorithm(GARBAGE));
        assertThrows(RuntimeException.class, () -> Pkix.parseAlgorithmIdentifier(NOT_DER));

        // Proof of possession fails when the embedded public key is not the signing key:
        // the request claims keyB's public key but is signed with keyA.
        KeyPair keyA = rsa();
        KeyPair keyB = rsa();
        CertificationRequest mismatched = Pkix.certificationRequestBuilder()
                .subject(new X500Principal("CN=poison"))
                .publicKey(keyB.getPublic())
                .build(Pkix.signer(keyA.getPrivate(), SHA256_RSA));
        CertificationRequest parsed = Pkix.parseCertificationRequest(mismatched.encoded());
        assertFalse(parsed.verifySelfSignature(), "PoP must fail when the CSR key does not match the signer");
    }
}
