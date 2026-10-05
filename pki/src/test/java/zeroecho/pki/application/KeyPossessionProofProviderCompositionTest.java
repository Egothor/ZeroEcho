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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.confirmation.KeyPossessionProofChallengeContext;
import zeroecho.pki.spi.confirmation.KeyPossessionProofCredential;
import zeroecho.pki.spi.confirmation.KeyPossessionProofDescriptor;
import zeroecho.pki.spi.confirmation.KeyPossessionProofPresentation;
import zeroecho.pki.spi.confirmation.KeyPossessionProofProvider;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;
import zeroecho.pki.spi.confirmation.KeyPossessionProofVerification;
import zeroecho.pki.spi.store.PkiStore;

final class KeyPossessionProofProviderCompositionTest {
    private static final Clock CLOCK = Clock.fixed(Instant.EPOCH, ZoneOffset.UTC);
    private static final String COMMITMENT = "1".repeat(64);

    @TempDir
    Path temporaryDirectory;

    @Test
    void composesEmptyAndOrderIndependentImmutableLookupWithoutCallingDescriptors() {
        KeyPossessionProofProviderComposition empty =
                KeyPossessionProofProviderComposition.compose(List.of());
        assertTrue(empty.find("missing.v1").isEmpty());

        AtomicInteger descriptorCalls = new AtomicInteger();
        TestProvider alpha = new TestProvider("alpha.v1", descriptorCalls);
        TestProvider beta = new TestProvider("beta.v2", descriptorCalls);
        KeyPossessionProofProviderComposition first =
                KeyPossessionProofProviderComposition.compose(List.of(alpha, beta));
        KeyPossessionProofProviderComposition reversed =
                KeyPossessionProofProviderComposition.compose(List.of(beta, alpha));

        assertSame(alpha, first.find("alpha.v1").orElseThrow());
        assertSame(beta, first.find("beta.v2").orElseThrow());
        assertSame(alpha, reversed.find("alpha.v1").orElseThrow());
        assertSame(beta, reversed.find("beta.v2").orElseThrow());
        assertEquals(first.providersBySuiteId().keySet(), reversed.providersBySuiteId().keySet());
        assertThrows(UnsupportedOperationException.class,
                () -> first.providersBySuiteId().put("other.v1", alpha));
        assertEquals(0, descriptorCalls.get());
    }

    @Test
    void runtimeDependenciesAndCompositionDefensivelyCopySourceList() {
        TestProvider provider = new TestProvider("copy.v1", new AtomicInteger());
        List<KeyPossessionProofProvider> source = new ArrayList<>(List.of(provider));
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.none()
                .withKeyPossessionProofProviders(source);
        source.clear();

        KeyPossessionProofProviderComposition composition =
                KeyPossessionProofProviderComposition.compose(
                        dependencies.keyPossessionProofProviders());
        assertSame(provider, composition.find("copy.v1").orElseThrow());
        assertThrows(UnsupportedOperationException.class,
                () -> dependencies.keyPossessionProofProviders().clear());
        assertTrue(dependencies.withAuditSink(event -> { })
                .keyPossessionProofProviders().contains(provider));
    }

    @Test
    void rejectsNullDuplicateInvalidAndFailingProviderIdentities() {
        TestProvider duplicate = new TestProvider("duplicate.v1", new AtomicInteger());
        assertThrows(NullPointerException.class, () -> new PkiSessionRuntimeDependencies(
                Optional.empty(), Optional.empty(), null, Optional.empty(), DashboardLiveSource.NONE));
        assertThrows(NullPointerException.class, () -> PkiSessionRuntimeDependencies.none()
                .withKeyPossessionProofProviders(Arrays.asList(duplicate, null)));
        assertThrows(IllegalArgumentException.class,
                () -> KeyPossessionProofProviderComposition.compose(List.of(duplicate, duplicate)));
        assertThrows(IllegalArgumentException.class,
                () -> KeyPossessionProofProviderComposition.compose(
                        List.of(new TestProvider("Invalid.v1", new AtomicInteger()))));
        assertThrows(NullPointerException.class,
                () -> KeyPossessionProofProviderComposition.compose(List.of(providerReturningNull())));
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> KeyPossessionProofProviderComposition.compose(List.of(providerThrowing())));
        assertEquals("suite-id-failure", failure.getMessage());
    }

    @Test
    void invalidProviderFailsBeforeSessionOpensStoreOrService() {
        AtomicInteger storesOpened = new AtomicInteger();
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.none()
                .withKeyPossessionProofProviders(List.of(
                        new TestProvider("not-canonical", new AtomicInteger())));
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("unused-store", Map.of()),
                new ProviderConfig("unused-audit", Map.of()), Optional.empty(), List.of(), List.of());

        assertThrows(IllegalArgumentException.class, () -> DefaultPkiSession.open(
                configuration, dependencies, CLOCK, bootstrap(storesOpened)));
        assertEquals(0, storesOpened.get());
    }

    @Test
    void proofPolicyRequiresAnExactDescriptorBeforeStoreOpen() {
        CredentialConfirmationProofRuntimePolicy policy = proofPolicy("proof.v1", COMMITMENT, 4_096);
        AtomicInteger storesOpened = new AtomicInteger();
        PkiSessionConfiguration configuration = unusedConfiguration();

        PkiSessionRuntimeDependencies missing = PkiSessionRuntimeDependencies.none()
                .withCredentialConfirmationProofPolicy(policy);
        assertThrows(IllegalArgumentException.class, () -> DefaultPkiSession.open(
                configuration, missing, CLOCK, bootstrap(storesOpened)));

        KeyPossessionProofProvider mismatching = descriptorProvider("proof.v1",
                descriptor("proof.v1", "2".repeat(64), 4_096));
        PkiSessionRuntimeDependencies mismatch = missing.withKeyPossessionProofProviders(
                List.of(mismatching));
        assertThrows(IllegalArgumentException.class, () -> DefaultPkiSession.open(
                configuration, mismatch, CLOCK, bootstrap(storesOpened)));

        KeyPossessionProofProvider nullDescriptor = new TestProvider("proof.v1", new AtomicInteger()) {
            @Override
            public KeyPossessionProofDescriptor descriptor(int rsaMaximumModulusBits) {
                return null;
            }
        };
        PkiSessionRuntimeDependencies invalid = missing.withKeyPossessionProofProviders(
                List.of(nullDescriptor));
        assertThrows(NullPointerException.class, () -> DefaultPkiSession.open(
                configuration, invalid, CLOCK, bootstrap(storesOpened)));

        KeyPossessionProofProvider throwing = new TestProvider("proof.v1", new AtomicInteger()) {
            @Override
            public KeyPossessionProofDescriptor descriptor(int rsaMaximumModulusBits) {
                throw new IllegalStateException("descriptor-failure");
            }
        };
        PkiSessionRuntimeDependencies failed = missing.withKeyPossessionProofProviders(List.of(throwing));
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> DefaultPkiSession.open(configuration, failed, CLOCK, bootstrap(storesOpened)));
        assertEquals("descriptor-failure", failure.getMessage());
        assertEquals(0, storesOpened.get());
    }

    @Test
    void exactProofPolicyAndDescriptorOpenOneUsableSession() throws Exception {
        CredentialConfirmationProofRuntimePolicy policy = proofPolicy("proof.v1", COMMITMENT, 4_096);
        KeyPossessionProofProvider provider = descriptorProvider("proof.v1",
                descriptor("proof.v1", COMMITMENT, 4_096));
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.none()
                .withKeyPossessionProofProviders(List.of(provider))
                .withCredentialConfirmationProofPolicy(policy);
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of());

        try (PkiSession session = PkiSession.open(configuration, dependencies, CLOCK)) {
            assertSame(session.confirmations(), session.confirmations());
        }
    }

    private static DefaultPkiSession.Bootstrap bootstrap(AtomicInteger storesOpened) {
        return new DefaultPkiSession.Bootstrap() {
            @Override public void validateStore(ProviderConfig configuration) { }
            @Override public void validateAudit(ProviderConfig configuration) { }
            @Override public PkiStore openStore(ProviderConfig configuration) {
                storesOpened.incrementAndGet();
                throw new AssertionError("Store must not open");
            }
            @Override public AuditSink openAudit(ProviderConfig configuration) {
                throw new AssertionError("Audit must not open");
            }
        };
    }

    private static PkiSessionConfiguration unusedConfiguration() {
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION,
                new ProviderConfig("unused-store", Map.of()),
                new ProviderConfig("unused-audit", Map.of()), Optional.empty(), List.of(), List.of());
    }

    private static CredentialConfirmationProofRuntimePolicy proofPolicy(
            String suiteId, String commitment, int rsaMaximumModulusBits) {
        return new CredentialConfirmationProofRuntimePolicy(
                new ConfirmationRealmBinding("production"),
                new CredentialConfirmationProofAudience(
                        "urn:uuid:123e4567-e89b-42d3-a456-426614174000"),
                Duration.ofMinutes(5L),
                new ConfirmationProofSuiteBinding(
                        new ConfirmationProofSuiteRef(suiteId, commitment), rsaMaximumModulusBits));
    }

    private static KeyPossessionProofDescriptor descriptor(
            String suiteId, String commitment, int rsaMaximumModulusBits) {
        return new KeyPossessionProofDescriptor(new ConfirmationProofSuiteBinding(
                new ConfirmationProofSuiteRef(suiteId, commitment), rsaMaximumModulusBits),
                32, rsaMaximumModulusBits / Byte.SIZE);
    }

    private static KeyPossessionProofProvider descriptorProvider(
            String suiteId, KeyPossessionProofDescriptor descriptor) {
        return new TestProvider(suiteId, new AtomicInteger()) {
            @Override
            public KeyPossessionProofDescriptor descriptor(int rsaMaximumModulusBits) {
                return descriptor;
            }
        };
    }

    private static KeyPossessionProofProvider providerReturningNull() {
        return new TestProvider("unused.v1", new AtomicInteger()) {
            @Override public String suiteId() { return null; }
        };
    }

    private static KeyPossessionProofProvider providerThrowing() {
        return new TestProvider("unused.v1", new AtomicInteger()) {
            @Override public String suiteId() { throw new IllegalStateException("suite-id-failure"); }
        };
    }

    private static class TestProvider implements KeyPossessionProofProvider {
        private final String suiteId;
        private final AtomicInteger descriptorCalls;

        private TestProvider(String suiteId, AtomicInteger descriptorCalls) {
            this.suiteId = suiteId;
            this.descriptorCalls = descriptorCalls;
        }

        @Override public String suiteId() { return suiteId; }

        @Override
        public KeyPossessionProofDescriptor descriptor(int rsaMaximumModulusBits) {
            descriptorCalls.incrementAndGet();
            throw new UnsupportedOperationException();
        }

        @Override
        public void validateCredential(KeyPossessionProofCredential credential) {
            throw new UnsupportedOperationException();
        }

        @Override
        public KeyPossessionProofPresentation createChallenge(KeyPossessionProofChallengeContext context) {
            throw new UnsupportedOperationException();
        }

        @Override
        public KeyPossessionProofVerification verify(KeyPossessionProofChallengeContext context,
                KeyPossessionProofCredential credential, KeyPossessionProofResponse response) {
            throw new UnsupportedOperationException();
        }
    }
}
