/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.profile.BuiltInCertificateProfileCatalog;
import zeroecho.pki.api.profile.BuiltInCertificateProfileTemplate;
import zeroecho.pki.api.profile.CertificateProfileDefinition;
import zeroecho.pki.api.profile.CertificateProfileKind;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.impl.audit.InMemoryAuditSink;
import zeroecho.pki.impl.core.DefaultProfileService;

/**
 * Atomic persistence and fail-closed lookup evidence for profile lifecycle state.
 */
final class FilesystemProfileLifecycleTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-07-30T10:00:00Z"), ZoneOffset.UTC);

    @Test
    void precommitFailuresPreserveAbsentVersionAndPreviousActivePointer(@TempDir Path directory)
            throws Exception {
        Path root = directory.resolve("store");
        BuiltInCertificateProfileTemplate template = builtIn("server-tls");
        byte[] versionTwo = version(template, 2, "Server TLS v2");
        try (FilesystemPkiStore store = store(root)) {
            DefaultProfileService service = service(store);
            CertificateProfileRef one = service.importBuiltIn(template);
            service.activateProfile("server-tls", 1);

            Path versionTemporary = new FsPaths(root).profileVersion("server-tls", 2)
                    .resolveSibling("2.bin.tmp");
            Files.createDirectories(versionTemporary);
            Files.writeString(versionTemporary.resolve("block"), "blocked");
            assertThrows(PkiException.class, () -> service.importProfile(versionTwo));
            assertTrue(service.getImportedVersion("server-tls", 2).isEmpty());
            assertFalse(Files.exists(new FsPaths(root).profileVersion("server-tls", 2)));

            Files.delete(versionTemporary.resolve("block"));
            Files.delete(versionTemporary);
            CertificateProfileRef two = service.importProfile(versionTwo);

            Path pointerTemporary = new FsPaths(root).profileActive("server-tls")
                    .resolveSibling("active.bin.tmp");
            Files.createDirectories(pointerTemporary);
            Files.writeString(pointerTemporary.resolve("block"), "blocked");
            assertThrows(PkiException.class, () -> service.activateProfile("server-tls", 2));
            assertEquals(one, service.getActiveReference("server-tls").orElseThrow());
            assertEquals(one, service.requireActiveProfile("server-tls").reference());
            assertFalse(one.equals(two));
        }
    }

    @Test
    void corruptAndNoncanonicalVersionsFailClosedAndCannotBeOverwritten(@TempDir Path directory)
            throws Exception {
        BuiltInCertificateProfileTemplate template = builtIn("server-tls");
        Path corruptRoot = directory.resolve("corrupt");
        try (FilesystemPkiStore store = store(corruptRoot)) {
            DefaultProfileService service = service(store);
            service.importBuiltIn(template);
            Path versionPath = new FsPaths(corruptRoot).profileVersion("server-tls", 1);
            Files.write(versionPath, new byte[] { 1, 2, 3 });
            byte[] corrupt = Files.readAllBytes(versionPath);
            assertCode(() -> service.getImportedVersion("server-tls", 1), "PROFILE_VERSION_CORRUPT");
            assertCode(() -> service.activateProfile("server-tls", 1), "PROFILE_VERSION_CORRUPT");
            assertTrue(service.getActiveReference("server-tls").isEmpty());
            assertCode(() -> service.importBuiltIn(template), "PROFILE_VERSION_CORRUPT");
            assertArrayEquals(corrupt, Files.readAllBytes(versionPath));
        }

        Path noncanonicalRoot = directory.resolve("noncanonical");
        try (FilesystemPkiStore store = store(noncanonicalRoot)) {
            byte[] noncanonical = (new String(template.canonicalJson(), StandardCharsets.UTF_8) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            ImportedCertificateProfileVersion invalid = new ImportedCertificateProfileVersion(
                    new CertificateProfileRef(template.definition().profileId(),
                            template.definition().profileVersion(), template.canonicalSha256()),
                    CertificateProfileDefinition.SCHEMA_VERSION, template.definition(),
                    noncanonical, CLOCK.instant());
            Path path = new FsPaths(noncanonicalRoot).profileVersion("server-tls", 1);
            FsOperations.ensureDir(path.getParent());
            Files.write(path, FsCodec.encode(FsCodec.PROFILE_VERSION, invalid));

            assertCode(() -> store.getProfileVersion("server-tls", 1), "PROFILE_VERSION_CORRUPT");
            assertCode(() -> service(store).importBuiltIn(template), "PROFILE_VERSION_CORRUPT");
        }

        Path hashMismatchRoot = directory.resolve("hash-mismatch");
        try (FilesystemPkiStore store = store(hashMismatchRoot)) {
            ImportedCertificateProfileVersion invalid = new ImportedCertificateProfileVersion(
                    new CertificateProfileRef(template.definition().profileId(),
                            template.definition().profileVersion(),
                            new byte[CertificateProfileRef.HASH_BYTES]),
                    CertificateProfileDefinition.SCHEMA_VERSION, template.definition(),
                    template.canonicalJson(), CLOCK.instant());
            Path path = new FsPaths(hashMismatchRoot).profileVersion("server-tls", 1);
            FsOperations.ensureDir(path.getParent());
            Files.write(path, FsCodec.encode(FsCodec.PROFILE_VERSION, invalid));

            assertCode(() -> store.getProfileVersion("server-tls", 1), "PROFILE_HASH_MISMATCH");
            assertCode(() -> service(store).importBuiltIn(template), "PROFILE_HASH_MISMATCH");
        }
    }

    @Test
    void unrelatedProfileIdsProceedWhileAnotherProfileCoordinatorIsHeld(@TempDir Path directory)
            throws Exception {
        try (FilesystemPkiStore store = store(directory.resolve("store"))) {
            DefaultProfileService service = service(store);
            Method acquire = FilesystemPkiStore.class.getDeclaredMethod("acquireProfileLock", String.class);
            Method release = FilesystemPkiStore.class.getDeclaredMethod("releaseProfileLock",
                    String.class, Class.forName(
                            "zeroecho.pki.impl.fs.FilesystemPkiStore$ProfileLockEntry"));
            acquire.setAccessible(true);
            release.setAccessible(true);
            CountDownLatch held = new CountDownLatch(1);
            CountDownLatch releaseHeld = new CountDownLatch(1);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<?> holder = executor.submit(() -> {
                    Object entry = invoke(acquire, store, "server-tls");
                    held.countDown();
                    try {
                        releaseHeld.await();
                    } finally {
                        invoke(release, store, "server-tls", entry);
                    }
                    return null;
                });
                assertTrue(held.await(5, TimeUnit.SECONDS));

                Future<CertificateProfileRef> unrelated =
                        executor.submit(() -> service.importBuiltIn(builtIn("email-signing")));
                CertificateProfileRef imported = unrelated.get(5, TimeUnit.SECONDS);
                assertEquals("email-signing", imported.profileId());
                assertTrue(service.getImportedVersion("email-signing", 1).isPresent());
                assertFalse(holder.isDone());

                releaseHeld.countDown();
                holder.get(5, TimeUnit.SECONDS);
            } finally {
                releaseHeld.countDown();
                executor.shutdownNow();
            }
        }
    }

    @Test
    void caKindsUseLifecycleAndOneLogicalIdCannotChangeKindAcrossVersions(
            @TempDir Path directory) throws Exception {
        Path root = directory.resolve("store");
        CertificateProfileRef rootRef;
        CertificateProfileRef intermediateRef;
        try (FilesystemPkiStore store = store(root)) {
            DefaultProfileService service = service(store);
            rootRef = service.importBuiltIn(builtIn("root-ca"));
            intermediateRef = service.importBuiltIn(builtIn("intermediate-ca"));
            assertTrue(service.getActiveReference("root-ca").isEmpty());
            assertTrue(service.getActiveReference("intermediate-ca").isEmpty());
            assertEquals(rootRef, service.activateProfile("root-ca", 1));
            assertEquals(intermediateRef, service.activateProfile("intermediate-ca", 1));
            assertEquals(CertificateProfileKind.ROOT_CA,
                    service.requireActiveProfile("root-ca").definition().certificateType());
            assertEquals(CertificateProfileKind.INTERMEDIATE_CA,
                    service.requireActiveProfile("intermediate-ca").definition().certificateType());

            byte[] sameKindVersion = version(builtIn("root-ca"), 2, "Root CA v2");
            CertificateProfileRef versionTwo = service.importProfile(sameKindVersion);
            assertEquals(2, versionTwo.profileVersion());

            byte[] conflictingKind = new String(builtIn("intermediate-ca").canonicalJson(),
                    StandardCharsets.UTF_8)
                    .replace("\"profileId\":\"intermediate-ca\"", "\"profileId\":\"root-ca\"")
                    .replace("\"profileVersion\":1", "\"profileVersion\":3")
                    .getBytes(StandardCharsets.UTF_8);
            assertCode(() -> service.importProfile(conflictingKind), "PROFILE_KIND_CONFLICT");
            assertTrue(service.getImportedVersion("root-ca", 3).isEmpty());
            assertEquals(rootRef, service.getActiveReference("root-ca").orElseThrow());
        }

        try (FilesystemPkiStore reopened = store(root)) {
            DefaultProfileService service = service(reopened);
            assertEquals(rootRef, service.getActiveReference("root-ca").orElseThrow());
            assertEquals(intermediateRef,
                    service.getActiveReference("intermediate-ca").orElseThrow());
            assertEquals(CertificateProfileKind.ROOT_CA,
                    service.requireActiveProfile("root-ca").definition().certificateType());
            assertEquals(CertificateProfileKind.INTERMEDIATE_CA,
                    service.requireActiveProfile("intermediate-ca").definition().certificateType());
        }
    }

    @Test
    void missingCorruptAndHashMismatchedPointersNeverFallback(@TempDir Path directory) throws Exception {
        BuiltInCertificateProfileTemplate template = builtIn("vpn-client");
        Path root = directory.resolve("store");
        try (FilesystemPkiStore store = store(root)) {
            DefaultProfileService service = service(store);
            CertificateProfileRef one = service.importBuiltIn(template);
            service.importProfile(version(template, 2, "VPN Client v2"));

            assertThrows(PkiException.class, () -> service.requireActiveProfile("vpn-client"));
            assertTrue(service.getActiveReference("vpn-client").isEmpty());

            Path pointer = new FsPaths(root).profileActive("vpn-client");
            FsOperations.writeAtomicStrict(pointer, FsCodec.encode(FsCodec.ACTIVE_PROFILE_REF,
                    new CertificateProfileRef("vpn-client", 3, new byte[CertificateProfileRef.HASH_BYTES])));
            assertActiveChainFailure(service, "vpn-client", "PROFILE_ACTIVE_POINTER_CORRUPT");

            FsOperations.writeAtomicStrict(pointer, FsCodec.encode(FsCodec.ACTIVE_PROFILE_REF,
                    new CertificateProfileRef("vpn-client", 1, new byte[CertificateProfileRef.HASH_BYTES])));
            assertActiveChainFailure(service, "vpn-client", "PROFILE_HASH_MISMATCH");

            Files.write(pointer, new byte[] { 7, 8, 9 });
            assertActiveChainFailure(service, "vpn-client", "PROFILE_ACTIVE_POINTER_CORRUPT");

            FsOperations.writeAtomicStrict(pointer, FsCodec.encode(FsCodec.ACTIVE_PROFILE_REF, one));
            Files.delete(new FsPaths(root).profileVersion("vpn-client", 1));
            assertActiveChainFailure(service, "vpn-client", "PROFILE_ACTIVE_POINTER_CORRUPT");
        }
    }

    @Test
    void snapshotPreflightsCorruptProfileArtifactsAndPathIdentityBeforeOutput(@TempDir Path directory)
            throws Exception {
        BuiltInCertificateProfileTemplate template = builtIn("server-tls");
        Path corruptRoot = directory.resolve("corrupt-store");
        Path corruptTarget = directory.resolve("corrupt-snapshot");
        try (FilesystemPkiStore store = store(corruptRoot)) {
            service(store).importBuiltIn(template);
            Path version = new FsPaths(corruptRoot).profileVersion("server-tls", 1);
            Files.write(version, new byte[] { 1, 2, 3 });

            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> store.exportSnapshot(corruptTarget, CLOCK.instant()));
            assertEquals("Historical snapshot failed: code=PROFILE_VERSION_CORRUPT",
                    failure.getMessage());
            assertEquals(null, failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
            assertFalse(failure.getMessage().contains(corruptRoot.toString()));
            assertFalse(failure.getMessage().contains("server-tls"));
            assertFalse(Files.exists(corruptTarget));
        }

        Path pathRoot = directory.resolve("path-store");
        Path pathTarget = directory.resolve("path-snapshot");
        try (FilesystemPkiStore store = store(pathRoot)) {
            service(store).importBuiltIn(template);
            Path original = new FsPaths(pathRoot).profileVersion("server-tls", 1);
            Path misplaced = pathRoot.resolve("profiles").resolve("by-id").resolve("id-wrong")
                    .resolve("versions").resolve("1.bin");
            FsOperations.ensureDir(misplaced.getParent());
            Files.write(misplaced, Files.readAllBytes(original));

            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> store.exportSnapshot(pathTarget, CLOCK.instant()));
            assertEquals("Historical snapshot failed: code=PROFILE_VERSION_CORRUPT",
                    failure.getMessage());
            assertFalse(Files.exists(pathTarget));
        }

        Path invalidRoot = directory.resolve("invalid-root-store");
        Path invalidTarget = directory.resolve("invalid-root-snapshot");
        try (FilesystemPkiStore store = store(invalidRoot)) {
            Files.writeString(invalidRoot.resolve("profiles"), "not-a-directory");
            IllegalStateException failure = assertThrows(IllegalStateException.class,
                    () -> store.exportSnapshot(invalidTarget, CLOCK.instant()));
            assertEquals("Historical snapshot failed: code=PROFILE_STORE_FAILURE",
                    failure.getMessage());
            assertEquals(null, failure.getCause());
            assertEquals(0, failure.getSuppressed().length);
            assertFalse(Files.exists(invalidTarget));
        }
    }

    private static byte[] version(BuiltInCertificateProfileTemplate template, int version, String displayName) {
        return new String(template.canonicalJson(), StandardCharsets.UTF_8)
                .replace("\"profileVersion\":1", "\"profileVersion\":" + version)
                .replace("\"displayName\":\"" + template.definition().displayName() + "\"",
                        "\"displayName\":\"" + displayName + "\"")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static FilesystemPkiStore store(Path root) throws Exception {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK);
    }

    private static DefaultProfileService service(FilesystemPkiStore store) {
        return new DefaultProfileService(store, CLOCK, new InMemoryAuditSink());
    }

    private static BuiltInCertificateProfileTemplate builtIn(String profileId) {
        return BuiltInCertificateProfileCatalog.load(FilesystemProfileLifecycleTest.class.getClassLoader()).stream()
                .filter(template -> profileId.equals(template.definition().profileId()))
                .findFirst().orElseThrow();
    }

    private static void assertActiveChainFailure(DefaultProfileService service, String profileId, String code) {
        PkiException referenceFailure = assertThrows(PkiException.class,
                () -> service.getActiveReference(profileId));
        PkiException profileFailure = assertThrows(PkiException.class,
                () -> service.requireActiveProfile(profileId));
        assertEquals("Profile lifecycle operation failed: code=" + code,
                referenceFailure.getMessage());
        assertEquals(referenceFailure.getMessage(), profileFailure.getMessage());
        assertEquals(null, referenceFailure.getCause());
        assertEquals(null, profileFailure.getCause());
        assertEquals(0, referenceFailure.getSuppressed().length);
        assertEquals(0, profileFailure.getSuppressed().length);
    }

    private static void assertCode(ThrowingOperation operation, String code) {
        PkiException failure = assertThrows(PkiException.class, operation::run);
        assertEquals("Profile lifecycle operation failed: code=" + code, failure.getMessage());
        assertEquals(null, failure.getCause());
        assertEquals(0, failure.getSuppressed().length);
    }

    @FunctionalInterface
    private interface ThrowingOperation {
        void run() throws Exception;
    }

    private static Object invoke(Method method, Object target, Object... arguments) {
        try {
            return method.invoke(target, arguments);
        } catch (IllegalAccessException impossible) {
            throw new IllegalStateException(impossible);
        } catch (InvocationTargetException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof RuntimeException runtime) {
                throw runtime;
            }
            throw new IllegalStateException(cause);
        }
    }
}
