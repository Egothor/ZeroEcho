/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.core;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.logging.Handler;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.fs.FilesystemPkiStore;
import zeroecho.pki.impl.fs.FsPkiStoreOptions;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Focused persisted profile lifecycle tests.
 */
final class DefaultProfileServiceTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-30T10:00:00Z"), ZoneOffset.UTC);

    @Test
    void builtInImportIsInactiveUntilExplicitActivationAndSurvivesRestart(@TempDir Path directory)
            throws Exception {
        BuiltInCertificateProfileTemplate template = builtIn("server-tls");
        Path root = directory.resolve("store");
        CertificateProfileRef reference;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            DefaultProfileService service = service(store);
            assertTrue(service.getActiveReference("server-tls").isEmpty());
            reference = service.importBuiltIn(template);
            assertTrue(service.getImportedVersion("server-tls", 1).isPresent());
            assertTrue(service.getActiveReference("server-tls").isEmpty());
            assertThrows(PkiException.class, () -> service.requireActiveProfile("server-tls"));
            assertEquals(reference, service.activateProfile("server-tls", 1));
            assertEquals(reference, service.requireActiveProfile("server-tls").reference());
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            assertEquals(reference, service(reopened).requireActiveProfile("server-tls").reference());
        }
    }

    @Test
    void repeatImportIsIdempotentAndConflictingVersionIsRejected(@TempDir Path directory) throws Exception {
        BuiltInCertificateProfileTemplate template = builtIn("server-tls");
        try (FilesystemPkiStore store = new FilesystemPkiStore(directory.resolve("store"),
                FsPkiStoreOptions.defaults(), CLOCK)) {
            DefaultProfileService service = service(store);
            CertificateProfileRef first = service.importProfile(template.canonicalJson());
            CertificateProfileRef repeated = service.importProfile(template.canonicalJson());
            assertEquals(first, repeated);
            String changed = new String(template.canonicalJson(), StandardCharsets.UTF_8)
                    .replace("\"displayName\":\"Server TLS\"", "\"displayName\":\"Changed\"");
            PkiException conflict = assertThrows(PkiException.class,
                    () -> service.importProfile(changed.getBytes(StandardCharsets.UTF_8)));
            assertTrue(conflict.getMessage().contains("PROFILE_VERSION_CONFLICT"));
            assertEquals(1, service.listImportedVersions("server-tls").size());
        }
    }

    @Test
    void activationSwitchesExactVersionWithoutRewritingVersionOne(@TempDir Path directory) throws Exception {
        BuiltInCertificateProfileTemplate template = builtIn("vpn-client");
        String versionTwoText = new String(template.canonicalJson(), StandardCharsets.UTF_8)
                .replace("\"profileVersion\":1", "\"profileVersion\":2")
                .replace("\"displayName\":\"VPN Client\"", "\"displayName\":\"VPN Client v2\"");
        byte[] versionTwo = versionTwoText.getBytes(StandardCharsets.UTF_8);
        try (FilesystemPkiStore store = new FilesystemPkiStore(directory.resolve("store"),
                FsPkiStoreOptions.defaults(), CLOCK)) {
            DefaultProfileService service = service(store);
            CertificateProfileRef one = service.importProfile(template.canonicalJson());
            service.activateProfile("vpn-client", 1);
            CertificateProfileRef two = service.importProfile(versionTwo);
            assertEquals(one, service.requireActiveProfile("vpn-client").reference());
            assertFalse(one.equals(two));
            service.activateProfile("vpn-client", 2);
            assertEquals(two, service.requireActiveProfile("vpn-client").reference());
            assertEquals(List.of(1L, 2L), service.listImportedVersions("vpn-client").stream()
                    .map(version -> version.reference().profileVersion()).toList());
        }
    }

    @Test
    void historicalSnapshotFailsBeforeTargetCreationWhenActivePointerExists(@TempDir Path directory)
            throws Exception {
        Path target = directory.resolve("snapshot");
        try (FilesystemPkiStore store = new FilesystemPkiStore(directory.resolve("store"),
                FsPkiStoreOptions.defaults(), CLOCK)) {
            DefaultProfileService service = service(store);
            service.importBuiltIn(builtIn("email-signing"));
            service.activateProfile("email-signing", 1);
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> store.exportSnapshot(target, CLOCK.instant()));
            assertTrue(failure.getMessage().contains("PROFILE_ACTIVATION_HISTORY_UNAVAILABLE"));
            assertFalse(Files.exists(target));
        }
    }

    @Test
    void concurrentIdenticalAndConflictingImportsAreSerializedPerProfile(@TempDir Path directory)
            throws Exception {
        BuiltInCertificateProfileTemplate template = builtIn("server-tls");
        try (FilesystemPkiStore store = new FilesystemPkiStore(directory.resolve("store"),
                FsPkiStoreOptions.defaults(), CLOCK)) {
            DefaultProfileService service = service(store);
            List<CertificateProfileRef> identical = runConcurrently(
                    () -> service.importProfile(template.canonicalJson()),
                    () -> service.importProfile(template.canonicalJson()));
            assertEquals(identical.get(0), identical.get(1));
            assertEquals(1, service.listImportedVersions("server-tls").size());

            byte[] versionTwo = new String(template.canonicalJson(), StandardCharsets.UTF_8)
                    .replace("\"profileVersion\":1", "\"profileVersion\":2")
                    .getBytes(StandardCharsets.UTF_8);
            byte[] conflictingVersionTwo = new String(versionTwo, StandardCharsets.UTF_8)
                    .replace("\"displayName\":\"Server TLS\"", "\"displayName\":\"Changed v2\"")
                    .getBytes(StandardCharsets.UTF_8);
            List<Attempt> conflicting = runAttempts(
                    () -> service.importProfile(versionTwo),
                    () -> service.importProfile(conflictingVersionTwo));
            assertEquals(1L, conflicting.stream().filter(Attempt::succeeded).count());
            assertEquals(1L, conflicting.stream().filter(attempt -> attempt.message()
                    .contains("PROFILE_VERSION_CONFLICT")).count());
            assertEquals(2, service.listImportedVersions("server-tls").size());
        }
    }

    @Test
    void concurrentActivationsLeaveOneCompleteExactPointer(@TempDir Path directory) throws Exception {
        BuiltInCertificateProfileTemplate template = builtIn("vpn-client");
        byte[] versionTwo = new String(template.canonicalJson(), StandardCharsets.UTF_8)
                .replace("\"profileVersion\":1", "\"profileVersion\":2")
                .replace("\"displayName\":\"VPN Client\"", "\"displayName\":\"VPN Client v2\"")
                .getBytes(StandardCharsets.UTF_8);
        try (FilesystemPkiStore store = new FilesystemPkiStore(directory.resolve("store"),
                FsPkiStoreOptions.defaults(), CLOCK)) {
            DefaultProfileService service = service(store);
            CertificateProfileRef one = service.importProfile(template.canonicalJson());
            CertificateProfileRef two = service.importProfile(versionTwo);
            List<CertificateProfileRef> results = runConcurrently(
                    () -> service.activateProfile("vpn-client", 1),
                    () -> service.activateProfile("vpn-client", 2));
            assertTrue(results.contains(one));
            assertTrue(results.contains(two));
            CertificateProfileRef active = service.getActiveReference("vpn-client").orElseThrow();
            assertTrue(active.equals(one) || active.equals(two));
            assertEquals(active, service.requireActiveProfile("vpn-client").reference());
        }
    }

    @Test
    void activationRequiresAnImportedVersionAndRepeatedActivationIsIdempotent(@TempDir Path directory)
            throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(directory.resolve("store"),
                FsPkiStoreOptions.defaults(), CLOCK)) {
            DefaultProfileService service = service(store);
            PkiException missing = assertThrows(PkiException.class,
                    () -> service.activateProfile("server-tls", 1));
            assertTrue(missing.getMessage().contains("PROFILE_VERSION_NOT_FOUND"));
            assertTrue(service.getActiveReference("server-tls").isEmpty());

            CertificateProfileRef imported = service.importBuiltIn(builtIn("server-tls"));
            CertificateProfileRef first = service.activateProfile("server-tls", 1);
            CertificateProfileRef repeated = service.activateProfile("server-tls", 1);
            assertEquals(imported, first);
            assertEquals(first, repeated);
            assertEquals(first, service.getActiveReference("server-tls").orElseThrow());
            assertEquals(1, service.listImportedVersions("server-tls").size());
        }
    }

    @Test
    void lifecycleOperationsSanitizeStoreDiagnosticsAndAuditCodes() {
        String sentinel = "unsafe-profile-store-sentinel";
        InMemoryAuditSink audit = new InMemoryAuditSink();
        DefaultProfileService service = new DefaultProfileService(failingStore(sentinel), CLOCK, audit);
        CollectingHandler logs = new CollectingHandler();
        Logger root = Logger.getLogger("");
        root.addHandler(logs);
        try {
            assertSanitized(() -> service.importProfile(new byte[] { 1, 2, 3 }),
                    "PROFILE_IMPORT_VALIDATION_FAILED", sentinel);
            assertSanitized(() -> service.importProfile(builtIn("server-tls").canonicalJson()),
                    "PROFILE_IMPORT_FAILED", sentinel);
            assertSanitized(() -> service.activateProfile("server-tls", 1),
                    "PROFILE_ACTIVATION_FAILED", sentinel);
            assertSanitized(() -> service.requireActiveProfile("server-tls"),
                    "PROFILE_STORE_FAILURE", sentinel);
            assertSanitized(() -> service.getImportedVersion("server-tls", 1),
                    "PROFILE_STORE_FAILURE", sentinel);
            assertSanitized(() -> service.listImportedVersions("server-tls"),
                    "PROFILE_STORE_FAILURE", sentinel);
            assertSanitized(() -> service.getActiveReference("server-tls"),
                    "PROFILE_STORE_FAILURE", sentinel);
        } finally {
            root.removeHandler(logs);
            logs.close();
        }
        assertTrue(audit.snapshot().stream().flatMap(event -> event.details().values().stream())
                .noneMatch(value -> value.contains(sentinel)));
        assertFalse(logs.text().contains(sentinel));
    }

    private static DefaultProfileService service(FilesystemPkiStore store) {
        return new DefaultProfileService(store, CLOCK, new InMemoryAuditSink());
    }

    private static BuiltInCertificateProfileTemplate builtIn(String profileId) {
        return BuiltInCertificateProfileCatalog.load(DefaultProfileServiceTest.class.getClassLoader()).stream()
                .filter(template -> profileId.equals(template.definition().profileId()))
                .findFirst().orElseThrow();
    }

    private static PkiStore failingStore(String sentinel) {
        return (PkiStore) Proxy.newProxyInstance(PkiStore.class.getClassLoader(),
                new Class<?>[] { PkiStore.class }, (proxy, method, arguments) -> {
                    if (method.getDeclaringClass() == Object.class) {
                        return switch (method.getName()) {
                            case "hashCode" -> System.identityHashCode(proxy);
                            case "equals" -> proxy == arguments[0];
                            case "toString" -> "FailingPkiStore";
                            default -> throw new AssertionError("unexpected Object method");
                        };
                    }
                    throw new IllegalStateException(sentinel);
                });
    }

    private static void assertSanitized(Callable<?> operation, String code, String sentinel) {
        PkiException failure = assertThrows(PkiException.class, operation::call);
        assertEquals("Profile lifecycle operation failed: code=" + code, failure.getMessage());
        assertFalse(failure.getMessage().contains(sentinel));
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }

    private static <T> List<T> runConcurrently(Callable<T> first, Callable<T> second) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(2);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<T> firstResult = executor.submit(() -> {
                barrier.await();
                return first.call();
            });
            Future<T> secondResult = executor.submit(() -> {
                barrier.await();
                return second.call();
            });
            return List.of(firstResult.get(), secondResult.get());
        } finally {
            executor.shutdownNow();
        }
    }

    private static List<Attempt> runAttempts(Callable<CertificateProfileRef> first,
            Callable<CertificateProfileRef> second) throws Exception {
        CyclicBarrier barrier = new CyclicBarrier(2);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<CertificateProfileRef> firstResult = executor.submit(() -> {
                barrier.await();
                return first.call();
            });
            Future<CertificateProfileRef> secondResult = executor.submit(() -> {
                barrier.await();
                return second.call();
            });
            return List.of(attempt(firstResult), attempt(secondResult));
        } finally {
            executor.shutdownNow();
        }
    }

    private static Attempt attempt(Future<CertificateProfileRef> result) throws InterruptedException {
        try {
            return new Attempt(result.get(), "");
        } catch (ExecutionException failure) {
            return new Attempt(null, failure.getCause().getMessage());
        }
    }

    private record Attempt(CertificateProfileRef reference, String message) {
        private boolean succeeded() {
            return reference != null;
        }
    }

    private static final class CollectingHandler extends Handler {
        private final StringBuilder messages = new StringBuilder();

        @Override
        public void publish(LogRecord record) {
            if (record != null) {
                messages.append(record.getMessage());
                if (record.getThrown() != null) {
                    messages.append(record.getThrown().getMessage());
                }
            }
        }

        @Override
        public void flush() {
            // In-memory only.
        }

        @Override
        public void close() {
            // No external resource.
        }

        private String text() {
            return messages.toString();
        }
    }
}
