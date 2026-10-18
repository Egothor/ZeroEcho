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
package zeroecho.pki.impl.crypto.pkcs11;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.spi.ProviderConfig;

/**
 * Unit tests for {@link Pkcs11SigningProviderFactory}.
 *
 * <p>No HSM or PKCS#11 library is required. These tests cover configuration
 * validation, provider identity, and PIN reading — all paths that can be
 * exercised without hardware.</p>
 */
public final class Pkcs11SigningProviderFactoryTest {

    private final Pkcs11SigningProviderFactory factory = new Pkcs11SigningProviderFactory();

    @Test
    public void id_returnsCorrectIdentifier() {
        assertEquals("pkcs11", factory.id());
    }

    @Test
    public void supportedKeys_containsExpectedKeys() {
        Set<String> keys = factory.supportedKeys();
        assertTrue(keys.contains("pkcs11ConfigFile"), "pkcs11ConfigFile must be a supported key");
        assertTrue(keys.contains("pinVariable"), "pinVariable must be a supported key");
        assertTrue(keys.contains("slot"), "slot must be a supported key");
        assertTrue(keys.contains("sessionPoolSize"), "sessionPoolSize must be a supported key");
        assertTrue(keys.contains("supportedAlgorithms"), "supportedAlgorithms must be a supported key");
    }

    @Test
    public void validateConfig_missingPkcs11ConfigFile_throws() {
        ProviderConfig config = new ProviderConfig("pkcs11", Map.of(
                "pinVariable", "ZEROECHO_HSM_PIN"));
        assertThrows(IllegalArgumentException.class, () -> factory.validateConfig(config));
    }

    @Test
    public void validateConfig_missingPinVariable_throws() {
        ProviderConfig config = new ProviderConfig("pkcs11", Map.of(
                "pkcs11ConfigFile", "/etc/zeroecho/hsm.cfg"));
        assertThrows(IllegalArgumentException.class, () -> factory.validateConfig(config));
    }

    @Test
    public void validateConfig_blankPkcs11ConfigFile_throws() {
        ProviderConfig config = new ProviderConfig("pkcs11", Map.of(
                "pkcs11ConfigFile", "   ",
                "pinVariable", "ZEROECHO_HSM_PIN"));
        assertThrows(IllegalArgumentException.class, () -> factory.validateConfig(config));
    }

    @Test
    public void validateConfig_invalidSlot_throws() {
        ProviderConfig config = new ProviderConfig("pkcs11", Map.of(
                "pkcs11ConfigFile", "/etc/zeroecho/hsm.cfg",
                "pinVariable", "ZEROECHO_HSM_PIN",
                "slot", "notAnInteger"));
        assertThrows(IllegalArgumentException.class, () -> factory.validateConfig(config));
    }

    @Test
    public void validateConfig_negativeSlot_throws() {
        ProviderConfig config = new ProviderConfig("pkcs11", Map.of(
                "pkcs11ConfigFile", "/etc/zeroecho/hsm.cfg",
                "pinVariable", "ZEROECHO_HSM_PIN",
                "slot", "-1"));
        assertThrows(IllegalArgumentException.class, () -> factory.validateConfig(config));
    }

    @Test
    public void validateConfig_invalidSessionPoolSize_throws() {
        ProviderConfig config = new ProviderConfig("pkcs11", Map.of(
                "pkcs11ConfigFile", "/etc/zeroecho/hsm.cfg",
                "pinVariable", "ZEROECHO_HSM_PIN",
                "sessionPoolSize", "0"));
        assertThrows(IllegalArgumentException.class, () -> factory.validateConfig(config));
    }

    @Test
    public void validateConfig_validMinimalConfig_passes() {
        ProviderConfig config = new ProviderConfig("pkcs11", Map.of(
                "pkcs11ConfigFile", "/etc/zeroecho/hsm.cfg",
                "pinVariable", "ZEROECHO_HSM_PIN"));
        // Must not throw.
        factory.validateConfig(config);
    }

    @Test
    public void readPinFromEnv_envVarNotSet_throwsPkiException() {
        // Use a variable name that is extremely unlikely to be set in any environment.
        String absurdVarName = "ZEROECHO_PKI_PKCS11_TEST_PIN_VARIABLE_THAT_WILL_NEVER_BE_SET_12345XYZ";
        assertThrows(PkiException.class,
                () -> Pkcs11SigningProviderFactory.readPinFromEnv(absurdVarName));
    }

    @Test
    public void computeCommitment_producesDeterministicResult() {
        Set<String> algorithms = Set.of("SHA256withECDSA", "SHA384withECDSA");
        byte[] first = Pkcs11SigningProviderFactory.computeCommitment(
                "/etc/zeroecho/hsm.cfg", 0, algorithms).bytes();
        byte[] second = Pkcs11SigningProviderFactory.computeCommitment(
                "/etc/zeroecho/hsm.cfg", 0, algorithms).bytes();
        assertNotNull(first);
        assertEquals(32, first.length, "Commitment must be 32 bytes (SHA-256)");
        org.junit.jupiter.api.Assertions.assertArrayEquals(first, second,
                "Identical inputs must produce identical commitments");
    }

    @Test
    public void computeCommitment_differentSlotProducesDifferentResult() {
        Set<String> algorithms = Set.of("SHA256withECDSA");
        byte[] slot0 = Pkcs11SigningProviderFactory.computeCommitment(
                "/etc/zeroecho/hsm.cfg", 0, algorithms).bytes();
        byte[] slot1 = Pkcs11SigningProviderFactory.computeCommitment(
                "/etc/zeroecho/hsm.cfg", 1, algorithms).bytes();
        assertNotNull(slot0);
        assertNotNull(slot1);
        org.junit.jupiter.api.Assertions.assertFalse(
                java.util.Arrays.equals(slot0, slot1),
                "Different slot indices must produce different commitments");
    }

    @Test
    public void defaultAlgorithms_containsExpectedJcaNames() {
        assertTrue(Pkcs11SigningProviderFactory.DEFAULT_ALGORITHMS.contains("SHA256withECDSA"));
        assertTrue(Pkcs11SigningProviderFactory.DEFAULT_ALGORITHMS.contains("SHA384withECDSA"));
        assertTrue(Pkcs11SigningProviderFactory.DEFAULT_ALGORITHMS.contains("SHA512withECDSA"));
        assertTrue(Pkcs11SigningProviderFactory.DEFAULT_ALGORITHMS.contains("RSASSA-PSS"));
    }
}
