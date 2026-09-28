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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;

final class PkiConfigurationChoicesTest {
    @Test
    void mergesKnownSourcesWithoutInventingRemoteInventoryAndTraversesEveryDistinctKey() {
        AtomicInteger scans = new AtomicInteger();
        PkiStore store = store(visitor -> {
            for (int i = 1002; i >= 0; i--) { visitor.accept(new KeyRef("key-" + String.format(java.util.Locale.ROOT, "%04d", i))); }
            visitor.accept(new KeyRef("key-0000"));
        }, scans);
        SigningProvider provider = provider(new AtomicInteger());
        PublicationTarget target = new PublicationTarget(PublicationTargetType.FILESYSTEM, "public-mirror");
        DefaultPkiConfigurationChoices source = new DefaultPkiConfigurationChoices(configuration(), store,
                Optional.of(provider), List.of(target), () -> { });
        List<String> all = new ArrayList<>();
        Optional<String> cursor = Optional.empty();
        do {
            PkiConfigurationChoicesSource.Choices page = source.configurationChoices(125, cursor, CancellationSignal.NONE);
            assertEquals(List.of("remote-configured"), page.signingProviders());
            assertEquals(List.of("Ed25519", "RSA"), page.algorithms());
            assertEquals(List.of(target), page.publicationTargets());
            assertEquals(List.of("x509"), page.formats().stream().map(value -> value.value()).toList());
            assertTrue(page.keys().size() <= 125);
            all.addAll(page.keys().stream().map(KeyRef::value).toList());
            cursor = page.nextCursor();
        } while (cursor.isPresent());
        assertEquals(1004, all.size());
        assertEquals(all.stream().distinct().sorted().toList(), all);
        assertEquals("topology-only", all.getLast());
        assertEquals(9, scans.get());
    }

    @Test
    void cancellationAndBoundsFailBeforeAnyProviderOrStoreRead() {
        AtomicInteger storeCalls = new AtomicInteger();
        AtomicInteger providerCalls = new AtomicInteger();
        PkiStore store = store(visitor -> { throw new AssertionError("Unexpected store access"); }, storeCalls);
        SigningProvider provider = provider(providerCalls);
        DefaultPkiConfigurationChoices source = new DefaultPkiConfigurationChoices(configuration(), store,
                Optional.of(provider), List.of(), () -> { });
        assertThrows(CancellationException.class, () -> source.configurationChoices(1, Optional.empty(), () -> true));
        assertThrows(IllegalArgumentException.class, () -> source.configurationChoices(0, Optional.empty(), CancellationSignal.NONE));
        assertThrows(IllegalArgumentException.class, () -> source.configurationChoices(1001, Optional.empty(), CancellationSignal.NONE));
        assertThrows(IllegalArgumentException.class, () -> source.configurationChoices(1, Optional.of(" "), CancellationSignal.NONE));
        assertEquals(0, storeCalls.get());
        assertEquals(0, providerCalls.get());
    }

    @Test
    void absentSignerReportsNoProviderOrAlgorithmsButKeepsPersistedKnownReferences() {
        PkiStore store = store(visitor -> visitor.accept(new KeyRef("persisted-key")), new AtomicInteger());
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("file", Map.of()), new ProviderConfig("file", Map.of()), Optional.empty(), List.of(), List.of());
        PkiConfigurationChoicesSource.Choices choices = new DefaultPkiConfigurationChoices(configuration, store,
                Optional.empty(), List.of(), () -> { }).configurationChoices(10, Optional.empty(), CancellationSignal.NONE);
        assertEquals(List.of(new KeyRef("persisted-key")), choices.keys());
        assertTrue(choices.signingProviders().isEmpty());
        assertTrue(choices.algorithms().isEmpty());
    }

    private static PkiStore store(Consumer<Consumer<KeyRef>> rows, AtomicInteger calls) {
        return (PkiStore) java.lang.reflect.Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    calls.incrementAndGet();
                    assertEquals("visitAuthorityKeyReferences", method.getName());
                    @SuppressWarnings("unchecked") Consumer<KeyRef> visitor = (Consumer<KeyRef>) arguments[0];
                    rows.accept(visitor);
                    return null;
                });
    }

    private static SigningProvider provider(AtomicInteger calls) {
        return (SigningProvider) java.lang.reflect.Proxy.newProxyInstance(SigningProvider.class.getClassLoader(), new Class<?>[] { SigningProvider.class },
                (proxy, method, arguments) -> {
                    calls.incrementAndGet();
                    return switch (method.getName()) {
                        case "id" -> "remote-configured";
                        case "supportedAlgorithms" -> Set.of("RSA", "Ed25519");
                        default -> throw new AssertionError("Unexpected provider inventory or key access: " + method.getName());
                    };
                });
    }

    private static PkiSessionConfiguration configuration() {
        PkiSessionConfiguration.SigningTopology topology = new PkiSessionConfiguration.SigningTopology(
                new PkiSessionConfiguration.SigningCoordinatorLimits(2, Duration.ofSeconds(30), Duration.ofSeconds(10),
                        Duration.ofMillis(100), Duration.ofSeconds(30)),
                List.of(new PkiSessionConfiguration.SigningKeyGroup(List.of(new KeyRef("topology-only"), new KeyRef("key-0000")),
                        new PkiSessionConfiguration.SigningLanePool(1, 1))),
                new PkiSessionConfiguration.SigningLanePool(1, 1));
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("file", Map.of("secret", "never-return-this")), new ProviderConfig("file", Map.of()),
                Optional.of(new PkiSessionConfiguration.SigningConfiguration(new ProviderConfig("remote", Map.of()),
                        "RSA", Duration.ofMinutes(1), Optional.empty(), topology, OptionalLong.empty())), List.of(), List.of());
    }
}
