/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.ca.CaKind;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevokedRecord;

/**
 * Black-box tests for {@link FilesystemPkiStore}.
 *
 * <p>
 * Tests focus on filesystem semantics (write-once, history, snapshot export)
 * and avoid dependencies on optional domain factories. Where the API uses
 * interfaces (notably {@link AttributeSet}), tests provide a minimal
 * deterministic stub.
 * </p>
 *
 * <p>
 * Every test routine prints its own name and prints {@code ...ok} on success.
 * Important intermediate values are printed with {@code "..."} prefix.
 * </p>
 */
public final class FilesystemPkiStoreTest {

    @TempDir
    Path tmp;

    @Test
    void writeOnceCredentialRejected() throws Exception {
        System.out.println("writeOnceCredentialRejected");

        Path root = tmp.resolve("store-write-once");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            Credential credential = TestObjects.minimalCredential();

            store.putCredential(credential);

            IllegalStateException ex = assertThrows(IllegalStateException.class, () -> store.putCredential(credential));
            assertNotNull(ex);
            System.out.println("...expected failure: " + safeMsg(ex.getMessage()));
        }

        printTree("store layout", root);
        System.out.println("writeOnceCredentialRejected...ok");
    }

    @Test
    void caHistoryCreatesCurrentAndHistory() throws Exception {
        System.out.println("caHistoryCreatesCurrentAndHistory");

        Path root = tmp.resolve("store-ca-history");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        PkiId caId;

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            CaRecord ca1 = TestObjects.minimalCaRecord();
            caId = ca1.caId();

            store.putCa(ca1);

            Path caHist = caHistoryDir(root, caId);
            waitForHistoryCount(caHist, 1, Duration.ofMillis(500));

            CaRecord ca2 = TestObjects.caVariant(ca1, CaState.DISABLED);
            store.putCa(ca2);

            waitForHistoryCount(caHist, 2, Duration.ofMillis(500));

            Path caDir = root.resolve("cas").resolve("by-id").resolve(FsUtil.safeId(caId));
            assertTrue(Files.exists(caDir.resolve("current.bin")));
            assertTrue(Files.isDirectory(caDir.resolve("history")));

            long historyCount = Files.list(caDir.resolve("history")).count();
            System.out.println("...historyCount=" + historyCount);
            assertTrue(historyCount >= 2L);

            Optional<CaRecord> loaded = store.getCa(caId);
            assertTrue(loaded.isPresent());
        }

        printTree("store layout", root);
        System.out.println("caHistoryCreatesCurrentAndHistory...ok");
    }

    @Test
    void revocationHistorySupportsOverwriteWithTrail() throws Exception {
        System.out.println("revocationHistorySupportsOverwriteWithTrail");

        Path root = tmp.resolve("store-revocations");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        PkiId credentialId;

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            RevokedRecord r1 = TestObjects.minimalRevocation();
            credentialId = r1.credentialId();

            store.putRevocation(r1);

            Path hist = revocationHistoryDir(root, credentialId);
            waitForHistoryCount(hist, 1, Duration.ofMillis(500));

            RevokedRecord r2 = new RevokedRecord(r1.credentialId(), r1.revocationTime().plusSeconds(1L), r1.reason(),
                    r1.attributes());

            store.putRevocation(r2);
            waitForHistoryCount(hist, 2, Duration.ofMillis(500));

            Path dir = root.resolve("revocations").resolve("by-credential").resolve(FsUtil.safeId(credentialId));
            assertTrue(Files.exists(dir.resolve("current.bin")));
            assertTrue(Files.isDirectory(dir.resolve("history")));

            long historyCount = Files.list(dir.resolve("history")).count();
            System.out.println("...historyCount=" + historyCount);
            assertTrue(historyCount >= 2L);
        }

        printTree("store layout", root);
        System.out.println("revocationHistorySupportsOverwriteWithTrail...ok");
    }

    @Test
    void snapshotExportSelectsCorrectHistoryVersions() throws Exception {
        System.out.println("snapshotExportSelectsCorrectHistoryVersions");

        Path root = tmp.resolve("store-snapshot");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        PkiId caId;

        // Arrange: create 4 CA versions (ACTIVE -> DISABLED -> RETIRED -> COMPROMISED).
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            CaRecord caV1 = TestObjects.minimalCaRecord();
            caId = caV1.caId();

            store.putCa(caV1);
            Path caHist = caHistoryDir(root, caId);
            waitForHistoryCount(caHist, 1, Duration.ofMillis(500));

            store.putCa(TestObjects.caVariant(caV1, CaState.DISABLED));
            waitForHistoryCount(caHist, 2, Duration.ofMillis(500));

            store.putCa(TestObjects.caVariant(caV1, CaState.RETIRED));
            waitForHistoryCount(caHist, 3, Duration.ofMillis(500));

            store.putCa(TestObjects.caVariant(caV1, CaState.COMPROMISED));
            waitForHistoryCount(caHist, 4, Duration.ofMillis(500));
        }

        printTree("store layout", root);

        // Read authoritative timestamps from history filenames (exactly as exporter
        // expects).
        Path caHist = caHistoryDir(root, caId);
        List<Long> tsMicros = listHistoryMicrosSorted(caHist);
        System.out.println("...ca history micros count=" + tsMicros.size());
        System.out.println("...ca history micros=" + tsMicros);

        assertTrue(tsMicros.size() >= 4);

        // Time points derived from those filenames:
        // beforeFirst -> must fail (strict)
        // atFirst -> selects v1 (ACTIVE)
        // atThird -> selects v3 (RETIRED)
        // afterFourth -> selects v4 (COMPROMISED)
        Instant beforeFirst = microsToInstant(tsMicros.get(0) - 1L);
        Instant atFirst = microsToInstant(tsMicros.get(0));
        Instant atThird = microsToInstant(tsMicros.get(2));
        Instant afterFourth = microsToInstant(tsMicros.get(3) + 1L);

        // Case 1: expected failure.
        Path snapFail = tmp.resolve("snapshot-fail");
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> {
            try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
                store.exportSnapshot(snapFail, beforeFirst);
            }
        });
        assertNotNull(ex);
        System.out.println("...expected failure ok: " + safeMsg(ex.getMessage()));

        // Case 2: at first -> v1 (ACTIVE).
        Path snap1 = tmp.resolve("snapshot-v1");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            store.exportSnapshot(snap1, atFirst);
        }
        printTree("snapshot v1 layout", snap1);
        CaRecord snapCa1 = readSnapshotCa(snap1, caId);
        System.out.println("...snapshot v1 state=" + snapCa1.state());
        assertEquals(CaState.ACTIVE, snapCa1.state());

        // Case 3: at third -> v3 (RETIRED).
        Path snap3 = tmp.resolve("snapshot-v3");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            store.exportSnapshot(snap3, atThird);
        }
        printTree("snapshot v3 layout", snap3);
        CaRecord snapCa3 = readSnapshotCa(snap3, caId);
        System.out.println("...snapshot v3 state=" + snapCa3.state());
        assertEquals(CaState.RETIRED, snapCa3.state());

        // Case 4: after fourth -> v4 (COMPROMISED).
        Path snap4 = tmp.resolve("snapshot-v4");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            store.exportSnapshot(snap4, afterFourth);
        }
        printTree("snapshot v4 layout", snap4);
        CaRecord snapCa4 = readSnapshotCa(snap4, caId);
        System.out.println("...snapshot v4 state=" + snapCa4.state());
        assertEquals(CaState.COMPROMISED, snapCa4.state());

        System.out.println("snapshotExportSelectsCorrectHistoryVersions...ok");
    }

    // -----------------------
    // Helper methods
    // -----------------------

    private static Path caHistoryDir(final Path storeRoot, final PkiId caId) {
        return storeRoot.resolve("cas").resolve("by-id").resolve(FsUtil.safeId(caId)).resolve("history");
    }

    private static Path revocationHistoryDir(final Path storeRoot, final PkiId credentialId) {
        return storeRoot.resolve("revocations").resolve("by-credential").resolve(FsUtil.safeId(credentialId))
                .resolve("history");
    }

    private static void waitForHistoryCount(final Path historyDir, final int expected, final Duration timeout)
            throws Exception {

        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            if (Files.isDirectory(historyDir)) {
                long count = Files.list(historyDir).filter(Files::isRegularFile).count();
                if (count >= expected) {
                    System.out.println("...historyDir=" + historyDir + " count=" + count);
                    return;
                }
            }
            Thread.sleep(5L);
        }
        throw new IllegalStateException(
                "history did not reach expected count " + expected + " in " + timeout + " at " + historyDir);
    }

    private static List<Long> listHistoryMicrosSorted(final Path historyDir) throws IOException {
        List<Long> out = new ArrayList<>();
        try (DirectoryStream<Path> ds = Files.newDirectoryStream(historyDir, "*.bin")) {
            for (Path p : ds) {
                String name = p.getFileName().toString();
                int dash = name.indexOf('-');
                if (dash <= 0) {
                    continue;
                }
                String ts = name.substring(0, dash);
                try {
                    out.add(Long.valueOf(ts));
                } catch (NumberFormatException ignore) {
                    // ignore
                }
            }
        }
        out.sort(Long::compareTo);
        return out;
    }

    private static Instant microsToInstant(final long tsMicros) {
        long sec = tsMicros / 1_000_000L;
        long micros = tsMicros % 1_000_000L;
        return Instant.ofEpochSecond(sec, micros * 1_000L);
    }

    private static CaRecord readSnapshotCa(final Path snapshotRoot, final PkiId caId) throws IOException {
        Path current = snapshotRoot.resolve("cas").resolve("by-id").resolve(FsUtil.safeId(caId)).resolve("current.bin");
        byte[] data = FsOperations.readAll(current);
        return FsCodec.decode(data, CaRecord.class);
    }

    private static void printTree(final String label, final Path root) throws IOException {
        System.out.println("..." + label + ": " + root);
        if (!Files.exists(root)) {
            System.out.println("...  <missing>");
            return;
        }
        Files.walk(root).sorted(Comparator.comparing(p -> root.relativize(p).toString())).forEach(p -> {
            try {
                String rel = root.relativize(p).toString();
                if (rel.isEmpty()) {
                    rel = ".";
                }
                if (Files.isDirectory(p)) {
                    System.out.println("...  [D] " + rel);
                } else if (Files.isRegularFile(p)) {
                    long size = Files.size(p);
                    System.out.println("...  [F] " + rel + " (" + size + " B)");
                } else {
                    System.out.println("...  [?] " + rel);
                }
            } catch (IOException e) {
                System.out.println("...  [!] " + p + " (io error)");
            }
        });
    }

    private static String safeMsg(final String s) {
        if (s == null) {
            return "<null>";
        }
        if (s.length() <= 80) {
            return s;
        }
        return s.substring(0, 80) + "...";
    }

    // -----------------------
    // Test object factories
    // -----------------------

    static final class TestObjects {

        private static long idCounter = 0L;

        private TestObjects() {
            // utility class
        }

        static CaRecord minimalCaRecord() throws Exception {
            Class<?> keyRef = Class.forName("zeroecho.pki.api.KeyRef");
            Class<?> subjectRef = Class.forName("zeroecho.pki.api.SubjectRef");

            PkiId caId = anyPkiId();
            Object issuerKeyRef = anyValue(keyRef);
            Object subject = anyValue(subjectRef);

            return new CaRecord(caId, CaKind.ROOT, CaState.ACTIVE, (zeroecho.pki.api.KeyRef) issuerKeyRef,
                    (zeroecho.pki.api.SubjectRef) subject, List.of());
        }

        static CaRecord caVariant(final CaRecord base, final CaState state) {
            return new CaRecord(base.caId(), base.kind(), state, base.issuerKeyRef(), base.subjectRef(),
                    base.caCredentials());
        }

        static CertificateProfile minimalProfile() throws Exception {
            Class<?> formatId = Class.forName("zeroecho.pki.api.FormatId");
            Object fmt = anyValue(formatId);

            Constructor<CertificateProfile> ctor = CertificateProfile.class.getConstructor(String.class, formatId,
                    String.class, List.class, List.class, Optional.class, boolean.class);

            return ctor.newInstance("profile-1", fmt, "Profile 1", List.of(), List.of(), Optional.empty(), true);
        }

        static Credential minimalCredential() throws Exception {
            Class<?> formatId = Class.forName("zeroecho.pki.api.FormatId");
            Class<?> issuerRef = Class.forName("zeroecho.pki.api.IssuerRef");
            Class<?> subjectRef = Class.forName("zeroecho.pki.api.SubjectRef");
            Class<?> validity = Class.forName("zeroecho.pki.api.Validity");
            Class<?> encodedObject = Class.forName("zeroecho.pki.api.EncodedObject");

            PkiId credentialId = anyPkiId();
            Object fmt = anyValue(formatId);
            Object iss = anyValue(issuerRef);
            Object sub = anyValue(subjectRef);
            Object val = anyValue(validity);
            String serial = "SERIAL-1";
            PkiId publicKeyId = anyPkiId();
            String profileId = "profile-1";
            CredentialStatus status = CredentialStatus.ISSUED;
            Object enc = anyValue(encodedObject);
            AttributeSet attrs = new EmptyAttributeSet();

            Constructor<Credential> ctor = Credential.class.getConstructor(PkiId.class, formatId, issuerRef, subjectRef,
                    validity, String.class, PkiId.class, String.class, CredentialStatus.class, encodedObject,
                    AttributeSet.class);

            return ctor.newInstance(credentialId, fmt, iss, sub, val, serial, publicKeyId, profileId, status, enc,
                    attrs);
        }

        static RevokedRecord minimalRevocation() throws Exception {
            PkiId cred = anyPkiId();
            AttributeSet attrs = new EmptyAttributeSet();
            Instant revTime = Instant.ofEpochSecond(1_700_000_000L);
            return new RevokedRecord(cred, revTime, RevocationReason.CESSATION_OF_OPERATION, attrs);
        }

        static PkiId anyPkiId() throws Exception {
            long n = nextIdCounter();
            UUID uuid = new UUID(0L, n);

            Class<PkiId> cls = PkiId.class;

            PkiId id = (PkiId) tryStaticNoArg(cls, "random");
            if (id != null) {
                return id;
            }
            id = (PkiId) tryStaticNoArg(cls, "newId");
            if (id != null) {
                return id;
            }

            PkiId byUuid = (PkiId) tryStatic1(cls, "of", UUID.class, uuid);
            if (byUuid != null) {
                return byUuid;
            }
            PkiId byUuid2 = (PkiId) tryCtor1(cls, UUID.class, uuid);
            if (byUuid2 != null) {
                return byUuid2;
            }

            String s = uuid.toString();
            PkiId byStr = (PkiId) tryStatic1(cls, "fromString", String.class, s);
            if (byStr != null) {
                return byStr;
            }
            PkiId byStr2 = (PkiId) tryStatic1(cls, "parse", String.class, s);
            if (byStr2 != null) {
                return byStr2;
            }
            PkiId byStr3 = (PkiId) tryCtor1(cls, String.class, s);
            if (byStr3 != null) {
                return byStr3;
            }

            throw new IllegalStateException("cannot construct PkiId reflectively");
        }

        static Object anyValue(final Class<?> type) throws Exception {
            Objects.requireNonNull(type, "type");

            // Validity has invariants; create it explicitly before record handling.
            if ("zeroecho.pki.api.Validity".equals(type.getName())) {
                Instant notBefore = Instant.ofEpochSecond(1_700_000_000L);
                Instant notAfter = notBefore.plusSeconds(86400L);
                Constructor<?> ctor = type.getConstructor(Instant.class, Instant.class);
                return ctor.newInstance(notBefore, notAfter);
            }

            if (AttributeSet.class.getName().equals(type.getName())) {
                return new EmptyAttributeSet();
            }

            if (type.isRecord()) {
                java.lang.reflect.RecordComponent[] components = type.getRecordComponents();
                Class<?>[] ctorTypes = new Class<?>[components.length];
                Object[] args = new Object[components.length];
                for (int i = 0; i < components.length; i++) {
                    ctorTypes[i] = components[i].getType();
                    args[i] = defaultValue(ctorTypes[i]);
                }
                Constructor<?> ctor = type.getDeclaredConstructor(ctorTypes);
                ctor.setAccessible(true);
                return ctor.newInstance(args);
            }

            Object v = tryStaticNoArg(type, "empty");
            if (v != null) {
                return v;
            }
            v = tryStaticNoArg(type, "defaultValue");
            if (v != null) {
                return v;
            }

            Constructor<?>[] ctors = type.getConstructors();
            for (Constructor<?> ctor : ctors) {
                if (ctor.getParameterCount() == 0) {
                    return ctor.newInstance();
                }
            }

            Object vs = tryCtor1(type, String.class, "x");
            if (vs != null) {
                return vs;
            }

            throw new IllegalStateException("cannot construct value: " + type.getName());
        }

        static Object defaultValue(final Class<?> t) throws Exception {
            if (t == String.class) {
                return "x";
            }
            if (t == int.class || t == Integer.class) {
                return Integer.valueOf(0);
            }
            if (t == long.class || t == Long.class) {
                return Long.valueOf(0L);
            }
            if (t == boolean.class || t == Boolean.class) {
                return Boolean.FALSE;
            }
            if (t == byte[].class) {
                return new byte[] { 0x01, 0x02 };
            }
            if (t == Optional.class) {
                return Optional.empty();
            }
            if (List.class.isAssignableFrom(t)) {
                return List.of();
            }
            if (t == Instant.class) {
                return Instant.ofEpochSecond(1_700_000_000L);
            }
            if (t == java.time.Duration.class) {
                return java.time.Duration.ZERO;
            }
            if (t == PkiId.class) {
                return anyPkiId();
            }
            if (AttributeSet.class.isAssignableFrom(t)) {
                return new EmptyAttributeSet();
            }
            if (t.isEnum()) {
                Object[] enums = t.getEnumConstants();
                return enums.length > 0 ? enums[0] : null;
            }
            return anyValue(t);
        }

        static Object tryStaticNoArg(final Class<?> type, final String method) {
            try {
                Method m = type.getMethod(method);
                return m.invoke(null);
            } catch (ReflectiveOperationException e) {
                return null;
            }
        }

        static Object tryStatic1(final Class<?> type, final String method, final Class<?> argType, final Object arg) {
            try {
                Method m = type.getMethod(method, argType);
                return m.invoke(null, arg);
            } catch (ReflectiveOperationException e) {
                return null;
            }
        }

        static Object tryCtor1(final Class<?> type, final Class<?> argType, final Object arg) {
            try {
                Constructor<?> c = type.getConstructor(argType);
                return c.newInstance(arg);
            } catch (ReflectiveOperationException e) {
                return null;
            }
        }

        private static long nextIdCounter() {
            idCounter = idCounter + 1L;
            return idCounter;
        }
    }

    /**
     * Minimal deterministic empty {@link AttributeSet} for tests.
     *
     * <p>
     * The production API defines {@link AttributeSet} as a passive interface
     * without factories. Tests only require an immutable empty set.
     * </p>
     */
    static final class EmptyAttributeSet implements AttributeSet {

        @Override
        public Set<AttributeId> ids() {
            return Set.of();
        }

        @Override
        public Optional<AttributeValue> get(final AttributeId id) {
            Objects.requireNonNull(id, "id");
            return Optional.empty();
        }

        @Override
        public List<AttributeValue> getAll(final AttributeId id) {
            Objects.requireNonNull(id, "id");
            return List.of();
        }
    }
}
