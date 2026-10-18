/* *****************************************************************************
 * Copyright (C) 2025, Leo Galambos
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

package zeroecho.pki.spi.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;

final class SigningInputCapabilitiesTest {
    private static final String RSA = BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm();
    private static final String EC = BootstrapAlgorithmIdentities.ECDSA_SHA384.canonicalForm();

    @Test
    void exactPrehashWinsAndRawLimitIsInclusive() {
        SigningInputCapabilities capabilities = new SigningInputCapabilities(10,
                Map.of(RSA, BootstrapAlgorithmIdentities.SHA256));
        assertEquals(SigningInputCapabilities.Mode.PREHASHED_DIGEST, capabilities.select(RSA, Long.MAX_VALUE));
        for (long length : new long[] { 0, 9, 10 }) {
            assertEquals(SigningInputCapabilities.Mode.RAW_MESSAGE, capabilities.select(EC, length));
        }
        assertThrows(IllegalArgumentException.class, () -> capabilities.select(EC, 11));
        assertThrows(IllegalArgumentException.class, () -> capabilities.select(RSA, -1));
        assertThrows(IllegalArgumentException.class, () -> new SigningInputCapabilities(0, Map.of()));
    }

    @Test
    void rejectsDigestSubstitutionPureEdPrivateFamiliesAndUnknownDigests() {
        assertThrows(IllegalArgumentException.class, () -> new SigningInputCapabilities(1,
                Map.of(RSA, BootstrapAlgorithmIdentities.SHA384)));
        assertThrows(IllegalArgumentException.class, () -> new SigningInputCapabilities(1,
                Map.of(BootstrapAlgorithmIdentities.ED25519_SIGNATURE.canonicalForm(),
                        BootstrapAlgorithmIdentities.SHA512)));
        AlgorithmIdentity privateSignature = new AlgorithmIdentity(AlgorithmIdentity.Kind.SIGNATURE,
                new AlgorithmIdentity.Family("private", "rsa"),
                new AlgorithmIdentity.DigestParameters(BootstrapAlgorithmIdentities.SHA256));
        assertThrows(IllegalArgumentException.class, () -> SigningInputCapabilities.requiredDigest(privateSignature));
    }

    @Test
    void exactPssParametersAndMapOrderAreCommitted() {
        AlgorithmIdentity pss = BootstrapAlgorithmIdentities.rsaPss(BootstrapAlgorithmIdentities.SHA256,
                BootstrapAlgorithmIdentities.SHA384, 20);
        SigningInputCapabilities parameters = new SigningInputCapabilities(10,
                Map.of(pss.canonicalForm(), BootstrapAlgorithmIdentities.SHA256));
        assertEquals(SigningInputCapabilities.Mode.PREHASHED_DIGEST, parameters.select(pss.canonicalForm(), 11));
        Map<String, AlgorithmIdentity> first = new LinkedHashMap<>();
        first.put(RSA, BootstrapAlgorithmIdentities.SHA256);
        first.put(EC, BootstrapAlgorithmIdentities.SHA384);
        Map<String, AlgorithmIdentity> reverse = new LinkedHashMap<>();
        reverse.put(EC, BootstrapAlgorithmIdentities.SHA384);
        reverse.put(RSA, BootstrapAlgorithmIdentities.SHA256);
        SigningProvider.ConfigurationCommitment backend = new SigningProvider.ConfigurationCommitment(new byte[32]);
        SigningInputCapabilities left = new SigningInputCapabilities(10, first);
        SigningInputCapabilities right = new SigningInputCapabilities(10, reverse);
        assertEquals(left.commitment(backend, first.keySet()), right.commitment(backend, reverse.keySet()));
        first.clear();
        assertEquals(2, left.prehashedDigests().size());
        assertThrows(UnsupportedOperationException.class, () -> left.prehashedDigests().clear());
        assertFalse(left.commitment(backend, reverse.keySet()).matches(
                new SigningInputCapabilities(11, reverse).commitment(backend, reverse.keySet())));
        assertFalse(left.commitment(backend, reverse.keySet()).matches(
                new SigningInputCapabilities(10, Map.of()).commitment(backend, reverse.keySet())));
        assertThrows(IllegalArgumentException.class, () -> left.commitment(backend, Set.of(RSA)));
    }

    @Test
    void rejectsRecursiveSignatureParametersBeforeGeneralIdentityParsing() {
        String nested = "digest=zeroecho.sha2-256.".repeat(8) + "none";
        String payload = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
                nested.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        String identity = "zealg:2:9:signature8:zeroecho14:rsa-pkcs1-v1_516:zeroecho.builtin"
                + payload.length() + ":" + payload;
        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> new SigningInputCapabilities(32, Map.of(identity, BootstrapAlgorithmIdentities.SHA256)));
        assertEquals("Unsupported nested prehash signature parameters", failure.getMessage());
    }
}
