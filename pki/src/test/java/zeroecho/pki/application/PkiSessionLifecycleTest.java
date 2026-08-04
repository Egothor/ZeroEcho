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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.testkit.InMemorySignatureWorkflow;
import zeroecho.pki.testkit.TestX509AlgorithmBindingProvider;

class PkiSessionLifecycleTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-04T00:00:00Z"), ZoneOffset.UTC);

    @TempDir
    Path temporaryDirectory;

    @Test
    void opensReusesAndDeterministicallyClosesOneSession() throws Exception {
        System.out.println("opensReusesAndDeterministicallyClosesOneSession");
        PkiSessionConfiguration configuration = configuration(temporaryDirectory.resolve("store"));
        PkiSession session = PkiSession.open(configuration);
        PkiOperationOutcome first = session.operations().execute(new PkiOperation.ValidateConfiguration(),
                CancellationSignal.NONE);
        PkiOperationOutcome second = session.operations().execute(new PkiOperation.ValidateConfiguration(),
                CancellationSignal.NONE);
        System.out.println("...executions=2");
        assertInstanceOf(PkiOperationOutcome.Success.class, first);
        assertInstanceOf(PkiOperationOutcome.Success.class, second);
        session.close();
        session.close();
        assertThrows(IllegalStateException.class, session::operations);
        assertThrows(UnsupportedOperationException.class,
                () -> ((PkiOperationOutcome.Success) first).result().fields().put("x", new PkiOperationValue.Text("y")));
        System.out.println("...ok");
    }

    @Test
    void ownsOneExplicitlyPrecomposedAuditSink() throws Exception {
        System.out.println("ownsOneExplicitlyPrecomposedAuditSink");
        AtomicInteger closes = new AtomicInteger();
        AuditSink shared = new AuditSink() {
            @Override
            public void record(zeroecho.pki.api.audit.AuditEvent event) {
                // The lifecycle assertion does not require emitting an event.
            }

            @Override
            public void close() {
                closes.incrementAndGet();
            }
        };
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.none().withAuditSink(shared);
        PkiSession session = PkiSession.open(configuration(temporaryDirectory.resolve("shared-audit-store")),
                dependencies);
        session.close();
        session.close();
        assertEquals(1, closes.get());
        System.out.println("...shared-audit-closes=" + closes.get());
        System.out.println("...ok");
    }

    @Test
    void explicitlyActivatesAuthorizedDeployerBindingProvider() throws Exception {
        System.out.println("explicitlyActivatesAuthorizedDeployerBindingProvider");
        PkiSessionConfiguration.BindingProviderConfiguration bindings =
                new PkiSessionConfiguration.BindingProviderConfiguration(TestX509AlgorithmBindingProvider.ID,
                        List.of(TestX509AlgorithmBindingProvider.PEN_ROOT,
                                TestX509AlgorithmBindingProvider.EGOTHOR_ROOT),
                        Optional.of("test-bindings-v1"));
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("binding-store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of(bindings));
        try (PkiSession session = PkiSession.open(configuration)) {
            assertTrue(session.algorithmBindings().find("test.ed25519.certificate.v1").isPresent());
            assertTrue(session.algorithmBindings().find("test.ed25519.crl.v1").isPresent());
            System.out.println("...bindings=" + session.algorithmBindings().bindings().size());
        }
        System.out.println("...ok");
    }

    @Test
    void profileValidationRejectsBindingOutsideActiveRegistry() throws Exception {
        System.out.println("profileValidationRejectsBindingOutsideActiveRegistry");
        PkiSessionConfiguration configuration = configuration(temporaryDirectory.resolve("profile-binding-store"));
        BuiltInCertificateProfileTemplate template = BuiltInCertificateProfileCatalog
                .load(getClass().getClassLoader()).stream().findFirst().orElseThrow();
        String document = new String(template.canonicalJson(), StandardCharsets.UTF_8).replace(
                "\"algorithmBindings\":{\"mode\":\"STANDARD_ONLY\"}",
                "\"algorithmBindings\":{\"mode\":\"EXPLICIT\",\"certificateSignature\":"
                        + "{\"bindingId\":\"deployer.inactive.certificate.v1\","
                        + "\"commitment\":\"inactive-binding-commitment\"}}");
        try (PkiSession session = PkiSession.open(configuration)) {
            PkiOperationOutcome outcome = session.operations().execute(
                    new PkiOperation.ValidateProfile(document.getBytes(StandardCharsets.UTF_8)),
                    CancellationSignal.NONE);
            PkiOperationOutcome.Failure failure = assertInstanceOf(PkiOperationOutcome.Failure.class, outcome);
            System.out.println("...classification=" + failure.classification());
            assertEquals(PkiOperationFailure.POLICY_REJECTION, failure.classification());
        }
        System.out.println("...ok");
    }

    @Test
    void rejectsUnauthorizedDeployerBindingRootBeforeStoreAllocation() {
        System.out.println("rejectsUnauthorizedDeployerBindingRootBeforeStoreAllocation");
        PkiSessionConfiguration.BindingProviderConfiguration bindings =
                new PkiSessionConfiguration.BindingProviderConfiguration(TestX509AlgorithmBindingProvider.ID,
                        List.of(TestX509AlgorithmBindingProvider.PEN_ROOT), Optional.of("test-bindings-v1"));
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("unused-binding").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), List.of(), List.of(bindings));
        assertThrows(IllegalArgumentException.class, () -> PkiSession.open(configuration));
        System.out.println("...ok");
    }

    @Test
    void validatesBeforeAllocationAndCleansPartialConstruction() {
        System.out.println("validatesBeforeAllocationAndCleansPartialConstruction");
        PkiSessionConfiguration configuration = configuration(temporaryDirectory.resolve("unused"));
        AtomicInteger storesOpened = new AtomicInteger();
        AtomicInteger storesClosed = new AtomicInteger();
        DefaultPkiSession.Bootstrap invalid = bootstrap(storesOpened, storesClosed, true, false, false, false);
        assertThrows(IllegalArgumentException.class,
                () -> DefaultPkiSession.open(configuration, CLOCK, invalid));
        assertEquals(0, storesOpened.get());

        DefaultPkiSession.Bootstrap partial = bootstrap(storesOpened, storesClosed, false, true, false, false);
        assertThrows(IllegalStateException.class,
                () -> DefaultPkiSession.open(configuration, CLOCK, partial));
        System.out.println("...partialStoreCloses=" + storesClosed.get());
        assertEquals(1, storesClosed.get());
        System.out.println("...ok");
    }

    @Test
    void preservesPrimaryAndSuppressedCloseFailures() throws Exception {
        System.out.println("preservesPrimaryAndSuppressedCloseFailures");
        PkiSessionConfiguration configuration = configuration(temporaryDirectory.resolve("unused-close"));
        DefaultPkiSession.Bootstrap bootstrap = bootstrap(new AtomicInteger(), new AtomicInteger(), false, false,
                true, true);
        PkiSession session = DefaultPkiSession.open(configuration, CLOCK, bootstrap);
        Exception failure = assertThrows(Exception.class, session::close);
        System.out.println("...suppressed=" + failure.getSuppressed().length);
        assertEquals("audit-close", failure.getMessage());
        assertEquals(1, failure.getSuppressed().length);
        assertInstanceOf(IOException.class, failure.getSuppressed()[0]);
        session.close();
        System.out.println("...ok");
    }

    @Test
    void configuredSigningRequiresExplicitUnlockAndCleansAllocatedResources() {
        System.out.println("configuredSigningRequiresExplicitUnlockAndCleansAllocatedResources");
        AtomicInteger storesOpened = new AtomicInteger();
        AtomicInteger storesClosed = new AtomicInteger();
        DefaultPkiSession.Bootstrap bootstrap = bootstrap(storesOpened, storesClosed, false, false, false, false);
        ProviderConfig placeholder = new ProviderConfig("test", Map.of());
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                placeholder, new ProviderConfig("x509-bc", Map.of()),
                temporaryDirectory.resolve("signing-bus").toString(), "RSA-2048-PSS-SHA256", Duration.ofSeconds(5),
                Optional.empty());
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("store-signing").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.of(signing), java.util.List.of());
        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> DefaultPkiSession.open(configuration, PkiSessionRuntimeDependencies.none(), CLOCK, bootstrap));
        System.out.println("...storesOpened=" + storesOpened.get() + ", storesClosed=" + storesClosed.get());
        assertEquals("Configured signing requires key-unlock capability", failure.getMessage());
        assertEquals(1, storesOpened.get());
        assertEquals(1, storesClosed.get());
        System.out.println("...ok");
    }

    @Test
    void opensExplicitPublisherCapabilityWithoutSigning() throws Exception {
        System.out.println("opensExplicitPublisherCapabilityWithoutSigning");
        ProviderConfig publisher = new ProviderConfig("filesystem",
                Map.of("root", temporaryDirectory.resolve("published").toString(), "targetId", "local-crls"));
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("store-publisher").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(), java.util.List.of(publisher));
        try (PkiSession session = PkiSession.open(configuration)) {
            System.out.println("...publicationConfigured=" + session.publications().isPresent());
            assertTrue(session.publications().isPresent());
            assertTrue(session.authorities().isEmpty());
        }
        System.out.println("...ok");
    }

    @Test
    void rejectsUnknownPublisherBeforeStoreAllocation() {
        System.out.println("rejectsUnknownPublisherBeforeStoreAllocation");
        Path storeRoot = temporaryDirectory.resolve("must-not-open");
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", storeRoot.toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.empty(),
                java.util.List.of(new ProviderConfig("unknown-publisher", Map.of())));
        assertThrows(IllegalStateException.class, () -> PkiSession.open(configuration));
        System.out.println("...storeAllocated=" + java.nio.file.Files.exists(storeRoot));
        assertTrue(java.nio.file.Files.notExists(storeRoot));
        System.out.println("...ok");
    }

    @Test
    void composesOneSharedSigningAndX509ServiceGraph() throws Exception {
        System.out.println("composesOneSharedSigningAndX509ServiceGraph");
        KeyRef keyRef = new KeyRef("managed:test-root");
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of(keyRef.value(), keyPair));
        ProviderConfig placeholder = new ProviderConfig("test", Map.of());
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                placeholder, new ProviderConfig("x509-bc", Map.of()),
                temporaryDirectory.resolve("composed-signing-bus").toString(), "SHA256withRSA",
                Duration.ofSeconds(5), Optional.empty());
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("composed-store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.of(signing), java.util.List.of());
        DefaultPkiSession.Bootstrap bootstrap = signingBootstrap(workflow);
        PkiSessionRuntimeDependencies dependencies = PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                () -> new KeyringPassword("unused-test-unlock".toCharArray()));
        try (PkiSession session = DefaultPkiSession.open(configuration, dependencies, CLOCK, bootstrap)) {
            System.out.println("...services=ca,request,issuance,status");
            assertTrue(session.authorities().isPresent());
            assertTrue(session.requests().isPresent());
            assertTrue(session.issuance().isPresent());
            assertTrue(session.statusObjects().isPresent());
            assertTrue(session.publications().isEmpty());
            BuiltInCertificateProfileTemplate root = BuiltInCertificateProfileCatalog
                    .load(getClass().getClassLoader()).stream()
                    .filter(candidate -> "root-ca".equals(candidate.definition().profileId())).findFirst()
                    .orElseThrow();
            session.profiles().importProfile(root.canonicalJson());
            session.profiles().activateProfile("root-ca", root.definition().profileVersion());
            PkiOperationOutcome outcome = session.operations().execute(new PkiOperation.CreateAuthority(
                    new FormatId("x509"), new SubjectRef("CN=Composed Root"), "root-ca", keyRef),
                    CancellationSignal.NONE);
            assertInstanceOf(PkiOperationOutcome.Success.class, outcome);
        }
        System.out.println("...ok");
    }

    private static PkiSessionConfiguration configuration(Path storeRoot) {
        return new PkiSessionConfiguration(1, new ProviderConfig("fs", Map.of("root", storeRoot.toString())),
                new ProviderConfig("memory", Map.of("size", "16")));
    }

    private static DefaultPkiSession.Bootstrap bootstrap(AtomicInteger storesOpened, AtomicInteger storesClosed,
            boolean invalidAudit, boolean failAuditOpen, boolean failAuditClose, boolean failStoreClose) {
        return new DefaultPkiSession.Bootstrap() {
            @Override
            public void validateStore(ProviderConfig configuration) {
                // valid
            }

            @Override
            public void validateAudit(ProviderConfig configuration) {
                if (invalidAudit) {
                    throw new IllegalArgumentException("invalid");
                }
            }

            @Override
            public void validateSignatureWorkflow(ProviderConfig configuration) {
                // valid test provider
            }

            @Override
            public void validateCredentialFramework(ProviderConfig configuration) {
                // valid test framework
            }

            @Override
            public PkiStore openStore(ProviderConfig configuration) {
                storesOpened.incrementAndGet();
                return proxyStore(() -> {
                    storesClosed.incrementAndGet();
                    if (failStoreClose) {
                        throw new IOException("store-close");
                    }
                });
            }

            @Override
            public AuditSink openAudit(ProviderConfig configuration) {
                if (failAuditOpen) {
                    throw new IllegalStateException("audit-open");
                }
                return new AuditSink() {
                    @Override
                    public void record(zeroecho.pki.api.audit.AuditEvent event) {
                        // no-op
                    }

                    @Override
                    public void close() {
                        if (failAuditClose) {
                            throw new IllegalStateException("audit-close");
                        }
                    }
                };
            }
        };
    }

    private static DefaultPkiSession.Bootstrap signingBootstrap(SignatureWorkflow workflow) {
        return new DefaultPkiSession.Bootstrap() {
            @Override
            public void validateStore(ProviderConfig configuration) {
                PkiBootstrap.validateStoreConfiguration(configuration);
            }

            @Override
            public void validateAudit(ProviderConfig configuration) {
                PkiBootstrap.validateAuditConfiguration(configuration);
            }

            @Override
            public PkiStore openStore(ProviderConfig configuration) {
                return PkiBootstrap.openStore(configuration);
            }

            @Override
            public AuditSink openAudit(ProviderConfig configuration) {
                return PkiBootstrap.openAudit(configuration);
            }

            @Override
            public void validateSignatureWorkflow(ProviderConfig configuration) {
                // Explicit deterministic test provider.
            }

            @Override
            public void validateCredentialFramework(ProviderConfig configuration) {
                PkiBootstrap.validateCredentialFrameworkConfiguration(configuration);
            }

            @Override
            public SignatureWorkflow openSignatureWorkflow(ProviderConfig configuration,
                    SignatureWorkflowRuntimeDependencies dependencies) {
                return workflow;
            }
        };
    }

    private static PkiStore proxyStore(CloseAction close) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(), new Class<?>[] { PkiStore.class },
                (proxy, method, arguments) -> {
                    if ("close".equals(method.getName())) {
                        close.close();
                        return null;
                    }
                    if ("toString".equals(method.getName())) {
                        return "test-store";
                    }
                    throw new UnsupportedOperationException(method.getName());
                });
    }

    @FunctionalInterface
    private interface CloseAction {
        void close() throws Exception;
    }
}
