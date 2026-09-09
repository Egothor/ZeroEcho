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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.impl.core.async.PkiSigningBus;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.spi.bootstrap.PkiBootstrap;
import zeroecho.pki.spi.crypto.SignatureWorkflow;
import zeroecho.pki.spi.crypto.SignatureWorkflowRuntimeDependencies;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
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
        zeroecho.pki.api.confirmation.CredentialConfirmationService confirmations =
                session.confirmations();
        assertTrue(confirmations == session.confirmations());
        PkiOperationOutcome first = session.operations().execute(new PkiOperation.ValidateConfiguration(),
                CancellationSignal.NONE);
        PkiOperationOutcome second = session.operations().execute(new PkiOperation.ValidateConfiguration(),
                CancellationSignal.NONE);
        System.out.println("...executions=2");
        assertInstanceOf(PkiOperationOutcome.Completed.class, first);
        assertInstanceOf(PkiOperationOutcome.Completed.class, second);
        session.close();
        session.close();
        assertThrows(IllegalStateException.class, session::operations);
        assertThrows(IllegalStateException.class, session::confirmations);
        assertThrows(IllegalStateException.class,
                () -> confirmations.get(new PkiId("closed-confirmation")));
        assertThrows(IllegalStateException.class,
                () -> confirmations.issueProofChallenge(
                        new zeroecho.pki.api.confirmation.CredentialConfirmationProofChallengeRequest(
                                new PkiId("closed-challenge"), 1L, "0".repeat(64))));
        assertThrows(UnsupportedOperationException.class,
                () -> ((PkiOperationOutcome.Completed) first).result().fields().put("x", new PkiOperationValue.Text("y")));
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
            PkiOperationOutcome.Failed failure = assertInstanceOf(PkiOperationOutcome.Failed.class, outcome);
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
    void passesExactSessionClockToStoreBootstrap() throws Exception {
        AtomicReference<PkiStoreRuntimeDependencies> observed = new AtomicReference<>();
        DefaultPkiSession.Bootstrap delegate = bootstrap(new AtomicInteger(), new AtomicInteger(),
                false, false, false, false);
        DefaultPkiSession.Bootstrap capturing = new DefaultPkiSession.Bootstrap() {
            @Override public void validateStore(ProviderConfig configuration) {
                delegate.validateStore(configuration);
            }
            @Override public void validateAudit(ProviderConfig configuration) {
                delegate.validateAudit(configuration);
            }
            @Override public PkiStore openStore(ProviderConfig configuration) {
                throw new AssertionError("Session bypassed store runtime dependencies");
            }
            @Override public PkiStore openStore(ProviderConfig configuration,
                    PkiStoreRuntimeDependencies dependencies) {
                observed.set(dependencies);
                return delegate.openStore(configuration);
            }
            @Override public AuditSink openAudit(ProviderConfig configuration) {
                return delegate.openAudit(configuration);
            }
        };
        try (PkiSession ignored = DefaultPkiSession.open(
                configuration(temporaryDirectory.resolve("clock-store")), CLOCK, capturing)) {
            assertSame(CLOCK, observed.get().clock());
        }
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
    void remoteSigningProviderReceivesUnlockButNotLocalLedger() throws Exception {
        System.out.println("remoteSigningProviderReceivesUnlockButNotLocalLedger");
        ProviderConfig placeholder = new ProviderConfig("test", Map.of());
        PkiSessionConfiguration.SigningConfiguration signing = new PkiSessionConfiguration.SigningConfiguration(
                placeholder, new ProviderConfig("x509-bc", Map.of()),
                "SHA256withRSA", Duration.ofSeconds(5),
                Optional.empty());
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("store-signing").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.of(signing), java.util.List.of());
        InMemorySignatureWorkflow remoteWorkflow = new InMemorySignatureWorkflow(Map.of());
        AtomicBoolean emptyDependenciesObserved = new AtomicBoolean();
        AtomicBoolean localParticipantObserved = new AtomicBoolean();
        PkiSessionRuntimeDependencies runtime = PkiSessionRuntimeDependencies.withKeyringUnlockProvider(
                () -> new zeroecho.core.storage.KeyringPassword(new char[] { 't', 'e', 's', 't' }));
        try (PkiSession session = DefaultPkiSession.open(configuration, runtime, CLOCK,
                signingBootstrap(remoteWorkflow, emptyDependenciesObserved, localParticipantObserved))) {
            assertTrue(session.authorities().isPresent());
            assertFalse(emptyDependenciesObserved.get());
            assertFalse(localParticipantObserved.get());
        }
        System.out.println("...ok");
    }

    @Test
    void foregroundDrainCancelsTimesOutWithoutClosingDependenciesAndRetries() throws Exception {
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of());
        AtomicInteger auditCloses = new AtomicInteger();
        AuditSink audit = new AuditSink() {
            @Override public void record(zeroecho.pki.api.audit.AuditEvent event) { }
            @Override public void close() { auditCloses.incrementAndGet(); }
        };
        DefaultPkiSession session = (DefaultPkiSession) DefaultPkiSession.open(
                signingConfiguration(temporaryDirectory.resolve("foreground-timeout"),
                        Duration.ofMillis(1), Duration.ofMillis(1)),
                PkiSessionRuntimeDependencies.none().withAuditSink(audit), CLOCK,
                signingBootstrap(workflow, new AtomicBoolean()));
        PkiSigningBus.ForegroundCall call = session.registerForegroundSigningCall(CancellationSignal.NONE);

        SigningExecutionException timeout = assertThrows(SigningExecutionException.class, session::close);

        assertEquals(SigningExecutionException.Classification.SHUTDOWN_TIMEOUT, timeout.classification());
        assertTrue(call.cancellation().isCancelled());
        assertEquals(0, auditCloses.get());
        SigningExecutionException rejected = assertThrows(SigningExecutionException.class,
                () -> session.registerForegroundSigningCall(CancellationSignal.NONE));
        assertEquals(SigningExecutionException.Classification.SHUTTING_DOWN, rejected.classification());

        call.close();
        session.close();
        assertEquals(1, auditCloses.get());
    }

    @Test
    void foregroundGraceAllowsCompletionBeforeDependencyClose() throws Exception {
        InMemorySignatureWorkflow workflow = new InMemorySignatureWorkflow(Map.of());
        AtomicInteger auditCloses = new AtomicInteger();
        AuditSink audit = new AuditSink() {
            @Override public void record(zeroecho.pki.api.audit.AuditEvent event) { }
            @Override public void close() { auditCloses.incrementAndGet(); }
        };
        DefaultPkiSession session = (DefaultPkiSession) DefaultPkiSession.open(
                signingConfiguration(temporaryDirectory.resolve("foreground-grace"),
                        Duration.ofSeconds(1), Duration.ofMillis(50)),
                PkiSessionRuntimeDependencies.none().withAuditSink(audit), CLOCK,
                signingBootstrap(workflow, new AtomicBoolean()));
        PkiSigningBus.ForegroundCall call = session.registerForegroundSigningCall(CancellationSignal.NONE);
        CompletableFuture<Void> closing = CompletableFuture.runAsync(() -> {
            try {
                session.close();
            } catch (Exception failure) {
                throw new CompletionException(failure);
            }
        });
        awaitForegroundQuiesce(session);

        assertFalse(call.cancellation().isCancelled());
        assertEquals(0, auditCloses.get());
        call.close();
        closing.get(2, TimeUnit.SECONDS);
        assertEquals(1, auditCloses.get());
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
                "SHA256withRSA", Duration.ofSeconds(5), Optional.empty());
        PkiSessionConfiguration configuration = new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", temporaryDirectory.resolve("composed-store").toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.of(signing), java.util.List.of());
        AtomicBoolean emptyDependenciesObserved = new AtomicBoolean();
        DefaultPkiSession.Bootstrap bootstrap = signingBootstrap(workflow, emptyDependenciesObserved);
        try (PkiSession session = DefaultPkiSession.open(configuration, PkiSessionRuntimeDependencies.none(), CLOCK,
                bootstrap)) {
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
            assertInstanceOf(PkiOperationOutcome.Completed.class, outcome);
            SigningReconciliationResult reconciliation = session.reconcileSigning(new SigningReconciliationRequest(
                    SigningReconciliationContinuation.start(), 16, 16, CLOCK.instant().plusSeconds(30),
                    Duration.ofSeconds(5), CancellationSignal.NONE));
            assertTrue(workflow.submittedSignCount() >= 1);
            assertEquals(0, reconciliation.retryable());
            assertTrue(emptyDependenciesObserved.get());
        }
        System.out.println("...ok");
    }

    private static PkiSessionConfiguration configuration(Path storeRoot) {
        return new PkiSessionConfiguration(1, new ProviderConfig("fs", Map.of("root", storeRoot.toString())),
                new ProviderConfig("memory", Map.of("size", "16")));
    }

    private static PkiSessionConfiguration signingConfiguration(Path storeRoot, Duration gracefulDrain,
            Duration forcedCancellation) {
        ProviderConfig workflow = new ProviderConfig("test", Map.of());
        PkiSessionConfiguration.SigningConfiguration signing =
                new PkiSessionConfiguration.SigningConfiguration(workflow,
                        new ProviderConfig("x509-bc", Map.of()), "SHA256withRSA", Duration.ofSeconds(5),
                        Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 1, 1,
                        gracefulDrain, forcedCancellation);
        return new PkiSessionConfiguration(3,
                new ProviderConfig("fs", Map.of("root", storeRoot.toString())),
                new ProviderConfig("memory", Map.of("size", "16")), Optional.of(signing), List.of());
    }

    private static void awaitForegroundQuiesce(DefaultPkiSession session) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(1);
        while (System.nanoTime() < deadline) {
            try (PkiSigningBus.ForegroundCall ignored =
                    session.registerForegroundSigningCall(CancellationSignal.NONE)) {
                Thread.onSpinWait();
            } catch (SigningExecutionException rejected) {
                assertEquals(SigningExecutionException.Classification.SHUTTING_DOWN, rejected.classification());
                return;
            }
        }
        throw new AssertionError("Foreground signing did not quiesce");
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

    private static DefaultPkiSession.Bootstrap signingBootstrap(SignatureWorkflow workflow,
            AtomicBoolean emptyDependenciesObserved) {
        return signingBootstrap(workflow, emptyDependenciesObserved, new AtomicBoolean());
    }

    private static DefaultPkiSession.Bootstrap signingBootstrap(SignatureWorkflow workflow,
            AtomicBoolean emptyDependenciesObserved, AtomicBoolean localParticipantObserved) {
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
                emptyDependenciesObserved.set(dependencies.keyringUnlockProvider().isEmpty());
                localParticipantObserved.set(dependencies.localSigningLedgerParticipant().isPresent());
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
