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
package zeroecho.pki.server.acme;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.server.spi.AcmeExternalAccountBindingProvider;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.ProviderConfig;

/** Production challenge-provider policy and explicit-composition coverage. */
class AcmeProviderSecurityTest {
    private static final Instant NOW = Instant.parse("2026-08-05T08:00:00Z");

    @Test
    void providersRequireExplicitStableIdentity() {
        System.out.println("providersRequireExplicitStableIdentity");
        Map<String, AcmeChallengeProvider> none = AcmeProviders.challenges(List.of(), getClass().getClassLoader());
        assertTrue(none.isEmpty());
        Map<String, AcmeChallengeProvider> selected = AcmeProviders.challenges(List.of(
                new ProviderConfig(Http01ChallengeProvider.ID, httpProperties(false))), getClass().getClassLoader());
        assertEquals(Set.of(Http01ChallengeProvider.ID), selected.keySet());
        assertThrows(IllegalArgumentException.class, () -> AcmeProviders.challenges(List.of(
                new ProviderConfig("missing-provider", Map.of())), getClass().getClassLoader()));
        assertThrows(UnsupportedOperationException.class, () -> selected.clear());
        System.out.println("...provider=" + selected.keySet().iterator().next());
        System.out.println("...ok");
    }

    @Test
    void httpProviderRejectsInternalTargetBeforeNetworkAccess() {
        System.out.println("httpProviderRejectsInternalTargetBeforeNetworkAccess");
        AcmeChallengeProvider.Result result = new Http01ChallengeProvider().validate(context("localhost"),
                new ProviderConfig(Http01ChallengeProvider.ID, httpProperties(false)), CancellationSignal.NONE);
        assertFalse(result.valid());
        assertEquals("TARGET_NETWORK_REJECTED", result.classification());
        System.out.println("...classification=" + result.classification());
        System.out.println("...ok");
    }

    @Test
    void dnsProviderRequiresExplicitNumericResolver() {
        System.out.println("dnsProviderRequiresExplicitNumericResolver");
        ProviderConfig invalid = new ProviderConfig(JndiDns01ChallengeProvider.ID, Map.of(
                "providerUrl", "dns://resolver.example.test", "timeoutMillis", "1000",
                "maximumRecords", "8", "maximumRecordBytes", "256", "maximumCnameDepth", "2"));
        assertThrows(IllegalArgumentException.class, () -> new JndiDns01ChallengeProvider().validate(
                context("example.test"), invalid, CancellationSignal.NONE));
        System.out.println("...search-suffix=disabled-by-absolute-name");
        System.out.println("...ok");
    }

    @Test
    void eabProviderIsClasspathInactiveUntilExplicitlySelected() {
        System.out.println("eabProviderIsClasspathInactiveUntilExplicitlySelected");
        assertTrue(AcmeProviders.eab(List.of(), getClass().getClassLoader()).isEmpty());
        Map<String, AcmeExternalAccountBindingProvider> selected = AcmeProviders.eab(List.of(
                new ProviderConfig(TestAcmeEabProvider.ID, Map.of())), getClass().getClassLoader());
        assertEquals(Set.of(TestAcmeEabProvider.ID), selected.keySet());
        System.out.println("...eab-provider=" + TestAcmeEabProvider.ID);
        System.out.println("...ok");
    }

    private static AcmeChallengeProvider.Context context(String name) {
        return new AcmeChallengeProvider.Context("directory:test:r1", "authorization:test",
                new AcmeState.Identifier(AcmeState.IdentifierType.DNS, name, false),
                AcmeState.ChallengeType.HTTP_01, "A".repeat(43), "A".repeat(43) + "." + "B".repeat(43),
                1, NOW, NOW.plus(Duration.ofSeconds(5)));
    }

    private static Map<String, String> httpProperties(boolean allowPrivate) {
        return Map.of("allowPrivate", Boolean.toString(allowPrivate), "timeoutMillis", "1000",
                "maximumBodyBytes", "4096", "maximumAddresses", "4");
    }
}
