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
package zeroecho.core.spec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spi.AlgorithmExecutionCapabilities;
import zeroecho.core.spi.AlgorithmExecutionCapability;

/**
 * Phase A regression tests for provider-independent identity and capability
 * contracts.
 */
public final class AlgorithmIdentityPhaseATest {

    @Test
    void exactIdentityAlgebraAndCanonicalRoundTrip() {
        System.out.println("exactIdentityAlgebraAndCanonicalRoundTrip");
        AlgorithmIdentity first = BootstrapAlgorithmIdentities.rsaPss(BootstrapAlgorithmIdentities.SHA384,
                BootstrapAlgorithmIdentities.SHA512, 40);
        AlgorithmIdentity second = BootstrapAlgorithmIdentities.rsaPss(BootstrapAlgorithmIdentities.SHA384,
                BootstrapAlgorithmIdentities.SHA512, 40);
        AlgorithmIdentity different = BootstrapAlgorithmIdentities.rsaPss(BootstrapAlgorithmIdentities.SHA384,
                BootstrapAlgorithmIdentities.SHA384, 40);
        AlgorithmIdentityCatalog extension = AlgorithmIdentityCatalog.extension(List.of(
                new AlgorithmIdentity(AlgorithmIdentity.Kind.SIGNATURE,
                        new AlgorithmIdentity.Family("example", "signature"),
                        new AlgorithmIdentity.DigestParameters(BootstrapAlgorithmIdentities.SHA384))));
        AlgorithmIdentityCatalog merged = BootstrapAlgorithmIdentities.catalog().merge(List.of(extension));

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
        assertNotEquals(first, different);
        assertEquals(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256,
                merged.resolve(BootstrapAlgorithmIdentities.RSA_PKCS1_SHA256.canonicalForm()).orElseThrow());
        assertFalse(first.canonicalForm().contains("BC"));
        assertFalse(first.canonicalForm().contains("Sun"));
        System.out.println("...canonical=" + abbreviate(first.canonicalForm()));
        System.out.println("...ok");
    }

    @Test
    void roleAndParameterContradictionsFailClosed() {
        System.out.println("roleAndParameterContradictionsFailClosed");
        assertThrows(IllegalArgumentException.class,
                () -> new AlgorithmSuite(BootstrapAlgorithmIdentities.SHA256,
                        BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY));
        assertThrows(IllegalArgumentException.class,
                () -> new AlgorithmIdentity.RsaPssParameters(BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY,
                        BootstrapAlgorithmIdentities.MGF1, BootstrapAlgorithmIdentities.SHA256, 32, 1));
        assertThrows(IllegalArgumentException.class,
                () -> BootstrapAlgorithmIdentities.rsaPss(BootstrapAlgorithmIdentities.SHA256,
                        BootstrapAlgorithmIdentities.SHA256, -1));
        assertThrows(IllegalArgumentException.class,
                () -> AlgorithmIdentityCatalog.extension(List.of(BootstrapAlgorithmIdentities.SHA256)));
        assertTrue(BootstrapAlgorithmIdentities.fromCompatibilityAlias("SHA1withRSA").isEmpty());
        assertTrue(BootstrapAlgorithmIdentities.fromCompatibilityAlias("provider-specific").isEmpty());
        System.out.println("...rejections=6");
        System.out.println("...ok");
    }

    @Test
    void parameterizedCapabilityDomainIsProviderMetadataOnly() {
        System.out.println("parameterizedCapabilityDomainIsProviderMetadataOnly");
        AlgorithmIdentity pss = BootstrapAlgorithmIdentities.rsaPss(BootstrapAlgorithmIdentities.SHA384,
                BootstrapAlgorithmIdentities.SHA512, 40);
        AlgorithmSuite suite = new AlgorithmSuite(pss, BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY);
        AlgorithmExecutionCapability capability = new TestPssCapability();
        AlgorithmExecutionCapabilities capabilities = new AlgorithmExecutionCapabilities(List.of(capability));

        assertEquals(1,
                capabilities.supporting(pss, suite, AlgorithmExecutionCapability.Direction.VERIFY).size());
        assertTrue(capabilities.supporting(pss, suite, AlgorithmExecutionCapability.Direction.SIGN).isEmpty());
        assertEquals(pss, suite.signature());
        System.out.println("...implementation=" + capability.implementationId());
        System.out.println("...ok");
    }

    private static String abbreviate(String value) {
        return value.length() <= 30 ? value : value.substring(0, 27) + "...";
    }

    /**
     * Typed test-only parameter domain proving that a central enum is unnecessary.
     */
    private static final class TestPssCapability implements AlgorithmExecutionCapability {

        @Override
        public String implementationId() {
            return "test.rsa-pss-verify";
        }

        @Override
        public String domainFingerprint() {
            return "rsa-pss|sha384|mgf1-sha512|salt=0..64|verify";
        }

        @Override
        public boolean supports(AlgorithmIdentity identity, AlgorithmSuite suite, Direction direction) {
            if (!(identity.parameters() instanceof AlgorithmIdentity.RsaPssParameters parameters)) {
                return false;
            }
            return identity.equals(suite.signature())
                    && BootstrapAlgorithmIdentities.RSA_PUBLIC_KEY.equals(suite.publicKey())
                    && BootstrapAlgorithmIdentities.SHA384.equals(parameters.hash())
                    && BootstrapAlgorithmIdentities.SHA512.equals(parameters.maskHash())
                    && parameters.saltLength() <= 64 && direction == Direction.VERIFY;
        }
    }
}
