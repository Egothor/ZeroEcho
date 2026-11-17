/*
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

package zeroecho.pki.api.ca;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Arrays;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.*;
import zeroecho.pki.api.profile.CertificateProfileRef;

/**
 * Contract and regression tests for issuer cryptographic binding.
 */
class IssuerCryptographicBindingTest {
    /**
     * Strict round trip commits complete public evidence and preserves value equality.
     */
    @Test void strictRoundTripCommitsCompletePublicEvidenceAndPreservesValueEquality() {
        var binding = binding();
        byte[] encoded = IssuerCryptographicBindingCodec.encode(binding);
        assertEquals(binding, IssuerCryptographicBindingCodec.decode(encoded));
        assertEquals(binding.commitment(), IssuerCryptographicBindingCodec.decode(encoded).commitment());
        var changed = new IssuerKeyBinding(new KeyRef("provider:other.priv"), binding.primary().publicKeyAlgorithm(),
                binding.primary().signatureAlgorithm(), binding.primary().signatureAlgorithmIdentifier(), "1".repeat(64));
        var different = new IssuerCryptographicBinding(1, binding.issuerId(), binding.authorityId(), binding.credentialId(), "X.509", changed,
                Optional.empty(), "2".repeat(64), binding.profile(), "3".repeat(64), binding.certificateHybridBaseline(), "4".repeat(64));
        assertNotEquals(binding.commitment(), different.commitment());
    }
    /**
     * Rejects unknown version flags truncation trailing bytes and malformed UTF-8.
     */
    @Test void rejectsUnknownVersionFlagsTruncationTrailingBytesAndMalformedUtf8() {
        byte[] encoded = IssuerCryptographicBindingCodec.encode(binding());
        for (int offset : new int[] {0, 5, 7}) {
            byte[] bad = encoded.clone(); bad[offset] ^= 1;
            assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(bad));
        }
        assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(Arrays.copyOf(encoded, encoded.length - 1)));
        assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(Arrays.copyOf(encoded, encoded.length + 1)));
        byte[] bad = encoded.clone(); bad[12] = (byte)0xff;
        assertThrows(IllegalArgumentException.class, () -> IssuerCryptographicBindingCodec.decode(bad));
    }
    /**
     * Rejects unpaired hybrid evidence.
     */
    @Test void rejectsUnpairedHybridEvidence() {
        var value = binding();
        assertThrows(IllegalArgumentException.class, () -> new IssuerCryptographicBinding(1, value.issuerId(), value.authorityId(), value.credentialId(), "X.509",
                value.primary(), Optional.empty(), "2".repeat(64), value.profile(), "3".repeat(64),
                IssuerCryptographicBinding.HybridSignatureBaseline.LEGACY_PRE_TBS, "4".repeat(64)));
    }
    private static IssuerCryptographicBinding binding() {
        PkiId ca = new PkiId("ca:test"), cert = new PkiId("cert:test");
        var key = new IssuerKeyBinding(new KeyRef("provider:test.priv"), BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.ECDSA_SHA384, new EncodedObject(Encoding.DER, java.util.HexFormat.of().parseHex("300a06082a8648ce3d040303")), "1".repeat(64));
        return new IssuerCryptographicBinding(1, IssuerGeneration.idFor(ca, cert), ca, cert, "X.509", key, Optional.empty(), "2".repeat(64),
                new CertificateProfileRef("test-ca", 1, new byte[32]), "3".repeat(64), IssuerCryptographicBinding.HybridSignatureBaseline.NONE,
                "4".repeat(64));
    }
}
