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
package zeroecho.pki.spi.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.Duration;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.spi.KeyringUnlockProvider;
import zeroecho.core.storage.KeyringPassword;
import zeroecho.core.storage.KeyringStore;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.audit.AccessContext;
import zeroecho.pki.api.audit.Principal;
import zeroecho.pki.api.audit.Purpose;
import zeroecho.pki.api.orch.SigningSubmissionId;
import zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSigningProviderFactory;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.audit.AuditSink;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.crypto.SigningProviderRuntimeDependencies;
import zeroecho.pki.spi.framework.CredentialFramework;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.PkiStoreRuntimeDependencies;
import zeroecho.pki.util.async.AsyncBus;

/**
 * JUnit 5 tests for {@link PkiBootstrap}.
 *
 * <p>
 * The tests validate provider selection and configuration conventions based on
 * {@link java.util.ServiceLoader} providers and {@link System#getProperties()}.
 * </p>
 *
 * <p>
 * Security note: tests must not print configuration values that might be
 * sensitive. Here we only print safe information (provider ids, class names,
 * and key presence).
 * </p>
 */
public final class PkiBootstrapTest {
    private static final char[] KEYRING_PASSWORD = { 'b', 'o', 'o', 't', 's', 't', 'r', 'a', 'p', '-', 't', 'e', 's',
            't' };
    private static final String SIGNING_NAMESPACE = "0123456789abcdef0123456789abcdef.zeroecho-lib";

    @TempDir
    private Path tempDir;

    private Properties savedProperties;

    @BeforeEach
    public void beforeEach() {
        System.out.println("beforeEach");
        this.savedProperties = (Properties) System.getProperties().clone();

        clearPrefix("zeroecho.pki.store.");
        clearPrefix("zeroecho.pki.audit.");
        clearPrefix("zeroecho.pki.framework.");
        clearPrefix("zeroecho.pki.async.");
        clearPrefix("zeroecho.pki.signing.provider.");

        System.clearProperty("zeroecho.pki.store");
        System.clearProperty("zeroecho.pki.audit");
        System.clearProperty("zeroecho.pki.framework");
        System.clearProperty("zeroecho.pki.async");
        System.clearProperty("zeroecho.pki.signing.provider");

        System.out.println("...tempDir=" + this.tempDir);
        System.out.println("...ok");
    }

    @AfterEach
    public void afterEach() {
        System.out.println("afterEach");
        System.setProperties(this.savedProperties);
        System.out.println("...ok");
    }

    @Test
    public void openStore_fs_usesTempRoot() {
        System.out.println("openStore_fs_usesTempRoot");

        System.setProperty("zeroecho.pki.store", "fs");
        System.setProperty("zeroecho.pki.store.root", this.tempDir.resolve("store").toString());

        PkiStore store = PkiBootstrap.openStore();
        assertNotNull(store);

        String storeClassName = store.getClass().getName();
        System.out.println("...storeClass=" + storeClassName);

        // Do not rely on implementation type at compile time; compare by name.
        assertEquals("zeroecho.pki.impl.fs.FilesystemPkiStore", storeClassName);

        System.out.println("...ok");
    }

    @Test
    public void configuredStoreReceivesExactRuntimeClockAndDefaultUsesSystemUtc() throws Exception {
        ProviderConfig explicitConfig = new ProviderConfig("fs",
                Map.of("root", tempDir.resolve("explicit-clock-store").toString()));
        Clock fixed = Clock.fixed(Instant.parse("2026-08-04T12:00:00Z"), ZoneOffset.UTC);
        try (PkiStore store = PkiBootstrap.openStore(explicitConfig,
                new PkiStoreRuntimeDependencies(fixed))) {
            assertSame(fixed, filesystemStoreClock(store));
        }

        ProviderConfig defaultConfig = new ProviderConfig("fs",
                Map.of("root", tempDir.resolve("default-clock-store").toString()));
        Instant before = Instant.now();
        try (PkiStore store = PkiBootstrap.openStore(defaultConfig)) {
            Clock clock = filesystemStoreClock(store);
            assertEquals(ZoneOffset.UTC, clock.getZone());
            assertFalse(clock.instant().isBefore(before));
        }
    }

    @Test void signingRuntimeClockIsExplicitAndLegacyFactoriesKeepSystemUtc() {
        Clock fixed = Clock.fixed(Instant.parse("2026-08-04T12:00:00Z"), ZoneOffset.UTC);
        KeyringUnlockProvider provider = () -> password();
        assertSame(fixed, SigningProviderRuntimeDependencies.withClock(fixed).clock());
        assertSame(fixed, SigningProviderRuntimeDependencies.withKeyringUnlockProvider(provider, fixed).clock());
        assertSame(provider, SigningProviderRuntimeDependencies.withKeyringUnlockProvider(provider, fixed)
                .keyringUnlockProvider().orElseThrow());
        assertEquals(ZoneOffset.UTC, SigningProviderRuntimeDependencies.none().clock().getZone());
        assertEquals(ZoneOffset.UTC, SigningProviderRuntimeDependencies.withKeyringUnlockProvider(provider).clock().getZone());
        assertThrows(NullPointerException.class, () -> SigningProviderRuntimeDependencies.withClock(null));
    }

    private static Clock filesystemStoreClock(PkiStore store) throws Exception {
        java.lang.reflect.Field field = store.getClass().getDeclaredField("clock");
        field.setAccessible(true);
        return (Clock) field.get(store);
    }

    @Test
    public void openAudit_defaultIsStdout() {
        System.out.println("openAudit_defaultIsStdout");

        // Per bootstrap: if no -Dzeroecho.pki.audit is set, default is "stdout".
        // This must work even if multiple audit providers exist.
        AuditSink sink = PkiBootstrap.openAudit();
        assertNotNull(sink);

        String sinkClassName = sink.getClass().getName();
        System.out.println("...auditClass=" + sinkClassName);

        assertEquals("zeroecho.pki.impl.audit.StdoutAuditSink", sinkClassName);

        System.out.println("...ok");
    }

    @Test
    public void openAudit_file_usesTempRoot() {
        System.out.println("openAudit_file_usesTempRoot");

        System.setProperty("zeroecho.pki.audit", "file");
        System.setProperty("zeroecho.pki.audit.root", this.tempDir.resolve("audit").toString());

        AuditSink sink = PkiBootstrap.openAudit();
        assertNotNull(sink);

        String sinkClassName = sink.getClass().getName();
        System.out.println("...auditClass=" + sinkClassName);

        assertEquals("zeroecho.pki.impl.audit.FileAuditSink", sinkClassName);

        System.out.println("...ok");
    }

    @Test
    public void openAudit_memory_acceptsSize() {
        System.out.println("openAudit_memory_acceptsSize");

        System.setProperty("zeroecho.pki.audit", "memory");
        System.setProperty("zeroecho.pki.audit.size", "123");

        AuditSink sink = PkiBootstrap.openAudit();
        assertNotNull(sink);

        String sinkClassName = sink.getClass().getName();
        System.out.println("...auditClass=" + sinkClassName);

        assertEquals("zeroecho.pki.impl.audit.InMemoryAuditSink", sinkClassName);

        System.out.println("...ok");
    }

    @Test
    public void openAudit_memory_rejectsInvalidSize() {
        System.out.println("openAudit_memory_rejectsInvalidSize");

        System.setProperty("zeroecho.pki.audit", "memory");
        System.setProperty("zeroecho.pki.audit.size", "abc");

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> PkiBootstrap.openAudit());
        System.out.println("...message=" + exception.getMessage());
        assertEquals("Configuration key 'size' must be an integer.", exception.getMessage());

        System.out.println("...ok");
    }

    @Test
    public void openCredentialFramework_explicitX509BcProvider() {
        System.out.println("openCredentialFramework_explicitX509BcProvider");

        System.setProperty("zeroecho.pki.framework", "x509-bc");

        CredentialFramework framework = PkiBootstrap.openCredentialFramework();
        assertNotNull(framework);

        String frameworkClassName = framework.getClass().getName();
        System.out.println("...frameworkClass=" + frameworkClassName);

        assertEquals("zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework", frameworkClassName);

        System.out.println("...ok");
    }

    @Test
    public void openCredentialFramework_x509Bc_byDefault() {
        System.out.println("openCredentialFramework_x509Bc_byDefault");

        CredentialFramework framework = PkiBootstrap.openCredentialFramework();
        assertNotNull(framework);

        String frameworkClassName = framework.getClass().getName();
        System.out.println("...frameworkClass=" + frameworkClassName);

        assertEquals("zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework", frameworkClassName);

        System.out.println("...ok");
    }

    @Test
    public void openCredentialFramework_x509Bc_ignoresUnknownKey() {
        System.out.println("openCredentialFramework_x509Bc_ignoresUnknownKey");

        System.setProperty("zeroecho.pki.framework", "x509-bc");
        System.setProperty("zeroecho.pki.framework.unused", "value");

        CredentialFramework framework = PkiBootstrap.openCredentialFramework();
        assertNotNull(framework);

        String frameworkClassName = framework.getClass().getName();
        System.out.println("...frameworkClass=" + frameworkClassName);

        assertEquals("zeroecho.pki.impl.framework.x509.bc.BcX509CredentialFramework", frameworkClassName);
        System.out.println("...ok");
    }

    @Test
    public void openAsync_file_usesTempLogPath() {
        System.out.println("openAsync_file_usesTempLogPath");

        System.setProperty("zeroecho.pki.async", "file");
        System.setProperty("zeroecho.pki.async.logPath", this.tempDir.resolve("async").resolve("async.log").toString());

        AsyncBus<PkiId, Principal, String, Object> bus = PkiBootstrap.openAsyncBus();
        assertNotNull(bus);

        String busClassName = bus.getClass().getName();
        System.out.println("...asyncClass=" + busClassName);

        assertEquals("zeroecho.pki.util.async.impl.DurableAsyncBus", busClassName);

        System.out.println("...ok");
    }

    @Test
    public void openSigningProvider_zeroEchoLib_usesConfiguredKeyringPath() throws Exception {
        System.out.println("openSigningProvider_zeroEchoLib_usesConfiguredKeyringPath");

        Path keyringPath = this.tempDir.resolve("workflow").resolve("keyring.zek");
        createSigningKeyring(keyringPath);
        System.setProperty("zeroecho.pki.signing.provider", "zeroecho-lib");
        System.setProperty("zeroecho.pki.signing.provider.keyringPath", keyringPath.toString());
        System.setProperty("zeroecho.pki.signing.provider.keyRefPrefix", "test-prefix:");
        System.setProperty("zeroecho.pki.signing.provider.requireComponentSuffix", "false");

        AtomicInteger acquisitions = new AtomicInteger();
        AtomicReference<KeyringPassword> suppliedPassword = new AtomicReference<>();
        KeyringUnlockProvider unlockProvider = () -> {
            acquisitions.incrementAndGet();
            KeyringPassword password = password();
            suppliedPassword.set(password);
            return password;
        };
        SigningProviderRuntimeDependencies dependencies =
                SigningProviderRuntimeDependencies.withKeyringUnlockProvider(unlockProvider);

        try (SigningProvider workflow = PkiBootstrap.openSigningProvider(dependencies)) {
            assertNotNull(workflow);
            String workflowClassName = workflow.getClass().getName();
            System.out.println("...workflowClass=" + workflowClassName);
            System.out.println("...unlockAcquisitions=" + acquisitions.get());

            assertEquals("zeroecho.pki.impl.crypto.zeroecholib.ZeroEchoLibSigningProvider", workflowClassName);
            assertEquals(1, acquisitions.get());
            assertTrue(suppliedPassword.get().isDestroyed());

            byte[] payload = { 1, 2, 3, 4 };
            AccessContext access = new AccessContext(new Principal("TEST", "bootstrap"), new Purpose("BOOTSTRAP_TEST"),
                    Optional.empty(), Optional.empty());
            PkiId submissionId = SigningSubmissionId.create(SIGNING_NAMESPACE, Instant.now(), new SecureRandom()).id();
            SigningProvider.SignRequest request = SigningProvider.SignRequest.create(submissionId,
                    SIGNING_NAMESPACE, workflow.configurationCommitment(), 1L, access,
                    new KeyRef("test-prefix:bootstrap"), "SHA256withRSA",
                    SigningProvider.ContentCommitment.sha256(payload), new ImmutableByteContent(payload),
                    Optional.of(Encoding.BINARY), Optional.empty());
            SigningProvider.CallControl control = new SigningProvider.CallControl(Instant.MAX,
                    zeroecho.core.io.CancellationSignal.NONE);
            workflow.validateSigningDomain(SIGNING_NAMESPACE, Duration.ofDays(90), Duration.ZERO);
            assertEquals(SigningProvider.ObservationState.SUCCEEDED,
                    workflow.dispatch(request, control).state());
        }

        try (KeyringPassword password = password(); KeyringStore reopened = KeyringStore.open(keyringPath, password)) {
            assertTrue(reopened.contains("bootstrap.prv"));
        }

        System.out.println("...ok");
    }

    @Test
    public void openSigningProvider_zeroEchoLib_requiresExplicitUnlockProvider() {
        System.out.println("openSigningProvider_zeroEchoLib_requiresExplicitUnlockProvider");

        configureWorkflow(this.tempDir.resolve("missing-provider"));

        PkiException exception = assertThrows(PkiException.class,
                () -> PkiBootstrap.openSigningProvider(SigningProviderRuntimeDependencies.none()));
        System.out.println("...code=" + exception.getMessage());

        assertEquals(ZeroEchoLibSigningProviderFactory.DC_KEYRING_UNLOCK_PROVIDER_REQUIRED, exception.getMessage());
        assertNull(exception.getCause());
        assertEquals(0, exception.getSuppressed().length);

        System.out.println("...ok");
    }

    @Test
    public void configuredSigningCompositionCapturesOnlyAllocatingFactoryCapabilities() {
        Path keyringPath = tempDir.resolve("selected-factory").resolve("keyring.zek");
        createSigningKeyring(keyringPath);
        AtomicInteger allocations = new AtomicInteger();
        SigningProviderRuntimeDependencies dependencies = SigningProviderRuntimeDependencies.withKeyringUnlockProvider(() -> {
            allocations.incrementAndGet();
            return password();
        });
        PkiBootstrap.SigningComposition composition = PkiBootstrap.openConfiguredSigningComposition(
                new ProviderConfig("zeroecho-lib", Map.of("keyringPath", keyringPath.toString())), dependencies);
        try (SigningProvider provider = composition.provider()) {
            assertEquals("zeroecho-lib", provider.id());
            assertEquals(1, allocations.get());
            assertEquals(List.of("zeroecho-lib.signing-provider"), composition.capabilities().stream()
                    .map(zeroecho.core.spi.AlgorithmExecutionCapability::implementationId).toList());
            assertThrows(UnsupportedOperationException.class, () -> composition.capabilities().clear());
        }
    }

    @Test
    public void openSigningProvider_zeroEchoLib_sanitizesUnlockProviderFailure() {
        System.out.println("openSigningProvider_zeroEchoLib_sanitizesUnlockProviderFailure");

        String sentinel = "DO_NOT_LOG_KEYRING_UNLOCK_SENTINEL";
        Path root = this.tempDir.resolve("provider-failure");
        Path keyringPath = root.resolve("keyring.zek");
        createSigningKeyring(keyringPath);
        configureWorkflow(root);

        List<LogRecord> records = new ArrayList<>();
        Logger bootstrapLogger = Logger.getLogger(PkiBootstrap.class.getName());
        Level oldLevel = bootstrapLogger.getLevel();
        Handler handler = collectingHandler(records);
        bootstrapLogger.addHandler(handler);
        bootstrapLogger.setLevel(Level.ALL);
        try {
            KeyringUnlockProvider failing = () -> {
                throw new IOException(sentinel);
            };
            PkiException exception = assertThrows(PkiException.class, () -> PkiBootstrap
                    .openSigningProvider(SigningProviderRuntimeDependencies.withKeyringUnlockProvider(failing)));
            System.out.println("...code=" + exception.getMessage());

            assertEquals(ZeroEchoLibSigningProviderFactory.DC_KEYRING_UNLOCK_PROVIDER_FAILED,
                    exception.getMessage());
            assertNull(exception.getCause());
            assertEquals(0, exception.getSuppressed().length);
            assertFalse(exception.toString().contains(sentinel));
            assertTrue(records.stream().noneMatch(record -> String.valueOf(record.getMessage()).contains(sentinel)));

            try (SigningProvider workflow = PkiBootstrap.openSigningProvider(
                    SigningProviderRuntimeDependencies.withKeyringUnlockProvider(() -> password()))) {
                assertNotNull(workflow);
            }
        } finally {
            bootstrapLogger.removeHandler(handler);
            bootstrapLogger.setLevel(oldLevel);
        }

        System.out.println("...ok");
    }

    @Test
    public void openSigningProvider_zeroEchoLib_wrongPasswordFailsUniformly() throws Exception {
        System.out.println("openSigningProvider_zeroEchoLib_wrongPasswordFailsUniformly");

        Path root = this.tempDir.resolve("wrong-password");
        createSigningKeyring(root.resolve("keyring.zek"));
        configureWorkflow(root);
        AtomicReference<KeyringPassword> suppliedPassword = new AtomicReference<>();
        KeyringUnlockProvider wrongProvider = () -> {
            KeyringPassword password = new KeyringPassword(new char[] { 'w', 'r', 'o', 'n', 'g' });
            suppliedPassword.set(password);
            return password;
        };

        PkiException exception = assertThrows(PkiException.class, () -> PkiBootstrap
                .openSigningProvider(
                        SigningProviderRuntimeDependencies.withKeyringUnlockProvider(wrongProvider)));
        assertEquals(ZeroEchoLibSigningProviderFactory.DC_KEYRING_OPEN_FAILED, exception.getMessage());
        assertNull(exception.getCause());
        assertEquals(0, exception.getSuppressed().length);
        assertTrue(suppliedPassword.get().isDestroyed());

        try (SigningProvider workflow = PkiBootstrap.openSigningProvider(
                SigningProviderRuntimeDependencies.withKeyringUnlockProvider(() -> password()))) {
            assertNotNull(workflow);
        }

        System.out.println("...ok");
    }

    @Test
    public void signingProviderBootstrapApi_requiresRuntimeDependencies() {
        System.out.println("signingProviderBootstrapApi_requiresRuntimeDependencies");

        java.lang.reflect.Method[] methods = PkiBootstrap.class.getDeclaredMethods();
        long workflowOpeners = java.util.Arrays.stream(methods)
                .filter(method -> "openSigningProvider".equals(method.getName())).count();
        java.lang.reflect.Method opener = java.util.Arrays.stream(methods)
                .filter(method -> "openSigningProvider".equals(method.getName())).findFirst().orElseThrow();
        System.out.println("...workflowOpeners=" + workflowOpeners);

        assertEquals(1L, workflowOpeners);
        assertEquals(List.of(SigningProviderRuntimeDependencies.class), List.of(opener.getParameterTypes()));
        assertTrue(java.util.Arrays.stream(PkiBootstrap.class.getDeclaredFields())
                .noneMatch(field -> KeyringUnlockProvider.class.equals(field.getType())));
        assertTrue(ProviderConfig.class.getRecordComponents()[1].getType().equals(Map.class));
        assertTrue(java.util.Arrays.stream(PkiBootstrap.class.getMethods())
                .noneMatch(method -> java.util.Arrays.stream(method.getParameterTypes()).anyMatch(String.class::equals)
                        && "openSigningProvider".equals(method.getName())));

        System.out.println("...ok");
    }

    @Test
    public void signingProviderRuntimeDependency_preservesPublicSpiBoundary() {
        KeyringUnlockProvider unlockProvider = () -> password();
        SigningProviderRuntimeDependencies dependencies =
                SigningProviderRuntimeDependencies.withKeyringUnlockProvider(unlockProvider);

        assertSame(unlockProvider, dependencies.keyringUnlockProvider().orElseThrow());
        assertFalse(java.util.Arrays.stream(SigningProviderRuntimeDependencies.class.getDeclaredMethods())
                .filter(method -> java.lang.reflect.Modifier.isPublic(method.getModifiers()))
                .map(java.lang.reflect.Method::toGenericString)
                .anyMatch(signature -> signature.contains("zeroecho.pki.impl.")));
    }

    @Test
    public void providerValidation_rejectsBackendIdMismatch() {
        System.out.println("providerValidation_rejectsBackendIdMismatch");

        zeroecho.pki.impl.fs.FilesystemPkiStoreProvider provider = new zeroecho.pki.impl.fs.FilesystemPkiStoreProvider();
        zeroecho.pki.spi.ProviderConfig config = new zeroecho.pki.spi.ProviderConfig("other",
                java.util.Map.of("root", this.tempDir.resolve("store").toString()));

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                () -> provider.validateConfig(config));
        System.out.println("...message=" + exception.getMessage());
        assertEquals("ProviderConfig backendId mismatch.", exception.getMessage());

        System.out.println("...ok");
    }

    private static void clearPrefix(String prefix) {
        Properties props = System.getProperties();
        for (Object keyObj : props.keySet().toArray()) {
            if (keyObj instanceof String) {
                String key = (String) keyObj;
                if (key.startsWith(prefix)) {
                    System.clearProperty(key);
                }
            }
        }
    }

    private void configureWorkflow(Path root) {
        System.setProperty("zeroecho.pki.signing.provider", "zeroecho-lib");
        System.setProperty("zeroecho.pki.signing.provider.keyringPath", root.resolve("keyring.zek").toString());
        System.setProperty("zeroecho.pki.signing.provider.keyRefPrefix", "test-prefix:");
        System.setProperty("zeroecho.pki.signing.provider.requireComponentSuffix", "false");
    }

    private static void createSigningKeyring(Path keyringPath) {
        try {
            KeyPair pair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            try (KeyringPassword password = password();
                    KeyringStore keyring = KeyringStore.create(keyringPath, password)) {
                keyring.putPrivate("bootstrap.prv", "RSA", pair.getPrivate());
                keyring.putPublic("bootstrap.pub", "RSA", pair.getPublic());
            }
        } catch (Exception failure) {
            throw new IllegalStateException("Unable to create bootstrap test keyring", failure);
        }
    }

    private static KeyringPassword password() {
        return new KeyringPassword(KEYRING_PASSWORD);
    }

    private static Handler collectingHandler(List<LogRecord> records) {
        return new Handler() {
            @Override
            public void publish(LogRecord record) {
                records.add(record);
            }

            @Override
            public void flush() {
                // No buffered output.
            }

            @Override
            public void close() {
                // No owned resource.
            }
        };
    }

}
