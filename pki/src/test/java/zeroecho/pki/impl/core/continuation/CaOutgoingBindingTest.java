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

package zeroecho.pki.impl.core.continuation;

import static org.junit.jupiter.api.Assertions.*;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.pki.api.*;
import zeroecho.pki.api.ca.IssuerKeyBinding;
import zeroecho.pkix.Pkix;
import zeroecho.pkix.AlgorithmIdentifier;

/**
 * Exact outgoing key selections survive durable encoding independently of incoming certificate algorithms.
 */
final class CaOutgoingBindingTest {
    /**
     * Round trips primary and alternative and rejects malformed or trailing evidence.
     */
    @Test void roundTripsPrimaryAndAlternativeAndRejectsMalformedOrTrailingEvidence() {
        var primary = new IssuerKeyBinding(new KeyRef("managed:primary"), BootstrapAlgorithmIdentities.EC_P384_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.ECDSA_SHA384, new EncodedObject(Encoding.DER,
                        Pkix.encodeAlgorithmIdentifier(AlgorithmIdentifier.absent("1.2.840.10045.4.3.3"))), "a".repeat(64));
        var alternative = new IssuerKeyBinding(new KeyRef("managed:alternative"), BootstrapAlgorithmIdentities.ML_DSA_87_PUBLIC_KEY,
                BootstrapAlgorithmIdentities.ML_DSA_87_SIGNATURE, new EncodedObject(Encoding.DER,
                        Pkix.encodeAlgorithmIdentifier(AlgorithmIdentifier.absent("2.16.840.1.101.3.4.3.19"))), "b".repeat(64));
        var value = new CaOutgoingBinding(primary, Optional.of(alternative), "c".repeat(64));
        assertEquals(value, CaOutgoingBinding.decode(value.encode()));
        assertEquals(value, CaOutgoingBinding.decodeForSubject(value.encodeForSubject(), primary.keyRef()));
        var largePrimary = new IssuerKeyBinding(new KeyRef("managed:" + "k".repeat(262_144)), primary.publicKeyAlgorithm(),
                primary.signatureAlgorithm(), primary.signatureAlgorithmIdentifier(), primary.subjectSpkiSha256());
        var large = new CaOutgoingBinding(largePrimary, Optional.of(alternative), "c".repeat(64));
        assertEquals(value.encodeForSubject().length(), large.encodeForSubject().length());
        assertEquals(large, CaOutgoingBinding.decodeForSubject(large.encodeForSubject(), largePrimary.keyRef()));
        assertThrows(IllegalArgumentException.class, () -> CaOutgoingBinding.decodeForSubject(value.encode(), primary.keyRef()));
        assertThrows(IllegalArgumentException.class, () -> CaOutgoingBinding.decode(value.encodeForSubject()));
        assertEquals(new CaOutgoingBinding(primary, Optional.empty(), "d".repeat(64)),
                CaOutgoingBinding.decode(new CaOutgoingBinding(primary, Optional.empty(), "d".repeat(64)).encode()));
        assertThrows(IllegalArgumentException.class, () -> CaOutgoingBinding.decode(value.encode() + "="));
        assertThrows(IllegalArgumentException.class, () -> CaOutgoingBinding.decode("x".repeat(1_398_105)));
        assertThrows(IllegalArgumentException.class, () -> new CaOutgoingBinding(primary, Optional.empty(), "invalid"));
    }
}
