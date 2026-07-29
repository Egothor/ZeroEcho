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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
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
 * Tests for {@link FilesystemPkiStore}.
 *
 * <p>
 * The tests are deterministic and do not use reflection. Snapshot export
 * semantics are tested using {@link FsPkiStoreOptions#strictSnapshotExport()}
 * configured appropriately.
 * </p>
 *
 * <p>
 * Output conventions:
 * </p>
 * <ul>
 * <li>Each test prints its own name at the start.</li>
 * <li>Each test prints {@code ...ok} on success.</li>
 * <li>Important intermediate state is printed with {@code ...} prefix.</li>
 * </ul>
 */
public final class FilesystemPkiStoreTest {

    @TempDir
    Path tmp;

    @Test
    void writeOnceCredentialRejected() throws Exception {
        System.out.println("writeOnceCredentialRejected");

        Path root = tmp.resolve("store-writeonce");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            Credential c1 = TestObjects.minimalCredential("SERIAL-1", "profile-1");
            store.putCredential(c1);

            RuntimeException ex = assertThrows(RuntimeException.class, () -> store.putCredential(c1));
            assertNotNull(ex);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("writeOnceCredentialRejected...ok");
    }

    @Test
    void caHistoryCreatesCurrentAndHistory() throws Exception {
        System.out.println("caHistoryCreatesCurrentAndHistory");

        Path root = tmp.resolve("store-ca-history");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            CaRecord ca1 = TestObjects.minimalCaRecord("ca-1", CaState.ACTIVE);
            store.putCa(ca1);

            CaRecord ca2 = new CaRecord(ca1.caId(), ca1.kind(), CaState.DISABLED, ca1.issuerKeyRef(), ca1.subjectRef(),
                    ca1.caCredentials());
            store.putCa(ca2);

            Optional<CaRecord> loaded = store.getCa(ca1.caId());
            assertTrue(loaded.isPresent());
            assertEquals(CaState.DISABLED, loaded.get().state());
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("caHistoryCreatesCurrentAndHistory...ok");
    }

    @Test
    void revocationHistorySupportsOverwriteWithTrail() throws Exception {
        System.out.println("revocationHistorySupportsOverwriteWithTrail");

        Path root = tmp.resolve("store-revocation-history");
        FsPkiStoreOptions options = FsPkiStoreOptions.defaults();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            RevokedRecord r1 = TestObjects.minimalRevocation("cred-rev-1", Instant.EPOCH.plusSeconds(10L),
                    RevocationReason.KEY_COMPROMISE);
            store.putRevocation(r1);

            RevokedRecord r2 = new RevokedRecord(r1.credentialId(), r1.revocationTime().plusSeconds(1L), r1.reason(),
                    r1.attributes());
            store.putRevocation(r2);

            Optional<RevokedRecord> loaded = store.getRevocation(r1.credentialId());
            assertTrue(loaded.isPresent());
            assertEquals(r2.revocationTime(), loaded.get().revocationTime());
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("revocationHistorySupportsOverwriteWithTrail...ok");
    }

    @Test
    void snapshotExportClonesNewRootNonStrict() throws Exception {
        System.out.println("snapshotExportClonesNewRootNonStrict");

        Path root = tmp.resolve("store-snapshot-basic");
        Path snapshot = tmp.resolve("snapshot-basic");

        FsPkiStoreOptions options = nonStrictSnapshotOptions();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            CaRecord ca1 = TestObjects.minimalCaRecord("ca-snap-1", CaState.ACTIVE);
            store.putCa(ca1);

            Instant at = Instant.now();
            store.putProfile(TestObjects.minimalProfile("profile-snap-1", true));

            store.exportSnapshot(snapshot, at);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("...snapshot tree:");
        dumpTree(snapshot);

        assertTrue(Files.exists(snapshot.resolve("VERSION")));
        assertTrue(Files.exists(snapshot.resolve("cas").resolve("by-id")));

        System.out.println("snapshotExportClonesNewRootNonStrict...ok");
    }

    @Test
    void snapshotExportWithMultipleObjectsNonStrictDoesNotFail() throws Exception {
        System.out.println("snapshotExportWithMultipleObjectsNonStrictDoesNotFail");

        Path root = tmp.resolve("store-snapshot-multi");
        Path snap1 = tmp.resolve("snapshot-multi-1");
        Path snap2 = tmp.resolve("snapshot-multi-2");

        FsPkiStoreOptions options = nonStrictSnapshotOptions();

        CaRecord caA = TestObjects.minimalCaRecord("ca-a", CaState.ACTIVE);
        CaRecord caB = TestObjects.minimalCaRecord("ca-b", CaState.ACTIVE);

        CertificateProfile pA = TestObjects.minimalProfile("profile-a", true);
        CertificateProfile pB = TestObjects.minimalProfile("profile-b", true);

        Instant at1;
        Instant at2;

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            store.putCa(caA);
            at1 = Instant.now();

            sleepMillis(120L);

            store.putCa(caB);
            store.putProfile(pA);
            at2 = Instant.now();

            sleepMillis(120L);

            store.putProfile(pB);

            // Export snapshots after all writes; in non-strict mode export must not fail.
            store.exportSnapshot(snap1, at1);
            store.exportSnapshot(snap2, at2);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("...snapshot1 tree:");
        dumpTree(snap1);

        System.out.println("...snapshot2 tree:");
        dumpTree(snap2);

        try (FilesystemPkiStore s2 = new FilesystemPkiStore(snap2, options)) {
            List<CaRecord> cas = s2.listCas();
            List<CertificateProfile> profiles = s2.listProfiles();

            Set<String> caIds = cas.stream().map(r -> r.caId().toString()).collect(Collectors.toSet());
            Set<String> profileIds = profiles.stream().map(CertificateProfile::profileId).collect(Collectors.toSet());

            System.out.println("...snapshot2 caIds: " + caIds);
            System.out.println("...snapshot2 profileIds: " + profileIds);

            assertTrue(caIds.contains("ca-a"));
            assertTrue(caIds.contains("ca-b"));
            assertTrue(profileIds.contains("profile-a"));
            assertTrue(profileIds.contains("profile-b"));
        }

        System.out.println("snapshotExportWithMultipleObjectsNonStrictDoesNotFail...ok");
    }

    @Test
    void snapshotExportStrictFailsWhenAtIsBeforeLaterInsert() throws Exception {
        System.out.println("snapshotExportStrictFailsWhenAtIsBeforeLaterInsert");

        Path root = tmp.resolve("store-snapshot-strict-fail");
        Path snapshot = tmp.resolve("snapshot-strict-fail");

        FsPkiStoreOptions options = strictSnapshotOptions();

        IllegalStateException ex;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            // Create CA first.
            store.putCa(TestObjects.minimalCaRecord("ca-strict-1", CaState.ACTIVE));

            // "at" is before the profile exists.
            Instant at = Instant.now();
            sleepMillis(120L);

            // Now create a new object that does not have history entry <= at.
            store.putProfile(TestObjects.minimalProfile("profile-strict-1", true));

            // Strict export must fail because current tree contains profile without history
            // <= at.
            ex = assertThrows(IllegalStateException.class, () -> store.exportSnapshot(snapshot, at));
        }

        System.out.println("...exception: " + shorten(ex.toString(), 200));
        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("snapshotExportStrictFailsWhenAtIsBeforeLaterInsert...ok");
    }

    @Test
    void snapshotExportStrictSucceedsWhenAtIsAfterAllWrites() throws Exception {
        System.out.println("snapshotExportStrictSucceedsWhenAtIsAfterAllWrites");

        Path root = tmp.resolve("store-snapshot-strict-ok");
        Path snapshot = tmp.resolve("snapshot-strict-ok");

        FsPkiStoreOptions options = strictSnapshotOptions();

        try (FilesystemPkiStore store = new FilesystemPkiStore(root, options)) {
            store.putCa(TestObjects.minimalCaRecord("ca-strict-ok", CaState.ACTIVE));
            store.putProfile(TestObjects.minimalProfile("profile-strict-ok", true));

            // "at" after all writes: strict export should succeed.
            Instant at = Instant.now();
            store.exportSnapshot(snapshot, at);
        }

        System.out.println("...store tree:");
        dumpTree(root);

        System.out.println("...snapshot tree:");
        dumpTree(snapshot);

        try (FilesystemPkiStore snap = new FilesystemPkiStore(snapshot, options)) {
            Set<String> caIds = snap.listCas().stream().map(r -> r.caId().toString()).collect(Collectors.toSet());
            Set<String> profileIds = snap.listProfiles().stream().map(CertificateProfile::profileId)
                    .collect(Collectors.toSet());

            System.out.println("...snapshot caIds: " + caIds);
            System.out.println("...snapshot profileIds: " + profileIds);

            assertTrue(caIds.contains("ca-strict-ok"));
            assertTrue(profileIds.contains("profile-strict-ok"));
        }

        System.out.println("snapshotExportStrictSucceedsWhenAtIsAfterAllWrites...ok");
    }

    private static FsPkiStoreOptions nonStrictSnapshotOptions() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        return new FsPkiStoreOptions(defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), false,
                defaults.signingOperationHorizon(), defaults.signingIdPermittedSkew());
    }

    private static FsPkiStoreOptions strictSnapshotOptions() {
        FsPkiStoreOptions defaults = FsPkiStoreOptions.defaults();
        return new FsPkiStoreOptions(defaults.caHistoryPolicy(), defaults.profileHistoryPolicy(),
                defaults.revocationHistoryPolicy(), defaults.workflowHistoryPolicy(), true,
                defaults.signingOperationHorizon(), defaults.signingIdPermittedSkew());
    }

    private static void sleepMillis(long ms) throws InterruptedException {
        Thread.sleep(ms);
    }

    private static void dumpTree(Path root) throws IOException {
        if (!Files.exists(root)) {
            System.out.println("...<missing> " + root);
            return;
        }
        List<Path> paths = Files.walk(root).sorted(Comparator.naturalOrder()).collect(Collectors.toList());
        for (Path p : paths) {
            Path rel = root.relativize(p);
            if (rel.toString().isEmpty()) {
                continue;
            }
            if (Files.isDirectory(p)) {
                System.out.println("..." + rel + "/");
            } else {
                long size = Files.size(p);
                System.out.println("..." + rel + " (" + size + " bytes)");
            }
        }
    }

    private static String shorten(String s, int max) {
        if (s == null) {
            return "null";
        }
        if (s.length() <= max) {
            return s;
        }
        return s.substring(0, Math.max(0, max - 3)) + "...";
    }

    /**
     * Test-only codec-friendly {@link AttributeSet} implementation (no proxies).
     *
     * @param entries serialized entries
     */
    public record TestAttributeSet(List<Entry> entries) implements AttributeSet {

        public record Entry(AttributeId id, List<AttributeValue> values) {

            public Entry {
                if (id == null) {
                    throw new IllegalArgumentException("id must not be null");
                }
                if (values == null) {
                    throw new IllegalArgumentException("values must not be null");
                }
            }
        }

        @Override
        public Set<AttributeId> ids() {
            return entries.stream().map(Entry::id).collect(Collectors.toUnmodifiableSet());
        }

        @Override
        public Optional<AttributeValue> get(AttributeId id) {
            if (id == null) {
                throw new IllegalArgumentException("id must not be null");
            }
            for (Entry e : entries) {
                if (e.id().equals(id)) {
                    if (e.values().isEmpty()) {
                        return Optional.empty();
                    }
                    return Optional.of(e.values().get(0));
                }
            }
            return Optional.empty();
        }

        @Override
        public List<AttributeValue> getAll(AttributeId id) {
            if (id == null) {
                throw new IllegalArgumentException("id must not be null");
            }
            for (Entry e : entries) {
                if (e.id().equals(id)) {
                    return List.copyOf(e.values());
                }
            }
            return List.of();
        }
    }

    /**
     * Deterministic domain fixtures.
     */
    static final class TestObjects {

        private static final AtomicLong SEQ = new AtomicLong(1L);

        static CaRecord minimalCaRecord(String caId, CaState state) {
            PkiId id = new PkiId(caId);

            KeyRef issuerKeyRef = new KeyRef("issuer-key-" + caId);
            SubjectRef subjectRef = new SubjectRef("CN=" + caId);

            Credential cred = minimalCredential("CA-" + caId, "profile-ca");
            List<Credential> caCredentials = List.of(cred);

            return new CaRecord(id, CaKind.ROOT, state, issuerKeyRef, subjectRef, caCredentials);
        }

        static CertificateProfile minimalProfile(String profileId, boolean active) {
            FormatId formatId = new FormatId("fmt-x509");
            String displayName = "Profile " + profileId;

            List<AttributeId> required = List.of(new AttributeId("req-1"));
            List<AttributeId> optional = List.of(new AttributeId("opt-1"));

            Optional<Duration> maxValidity = Optional.of(Duration.ofDays(365));

            return new CertificateProfile(profileId, formatId, displayName, required, optional, maxValidity, active);
        }

        static Credential minimalCredential(String serial, String profileId) {
            PkiId credentialId = new PkiId("cred-" + nextSeq());
            FormatId formatId = new FormatId("fmt-x509");

            IssuerRef issuerRef = new IssuerRef(new PkiId("issuer-" + nextSeq()));
            SubjectRef subjectRef = new SubjectRef("CN=subj-" + nextSeq());

            Instant notBefore = Instant.EPOCH;
            Instant notAfter = Instant.EPOCH.plusSeconds(60L);
            Validity validity = new Validity(notBefore, notAfter);

            PkiId publicKeyId = new PkiId("pk-" + nextSeq());

            CredentialStatus status = CredentialStatus.ISSUED;

            EncodedObject encoded = minimalEncodedObject();
            AttributeSet attrs = emptyAttributes();

            return new Credential(credentialId, formatId, issuerRef, subjectRef, validity, serial, publicKeyId,
                    profileId, status, encoded, attrs);
        }

        static RevokedRecord minimalRevocation(String credentialId, Instant when, RevocationReason reason) {
            PkiId id = new PkiId(credentialId);
            AttributeSet attrs = emptyAttributes();
            return new RevokedRecord(id, when, reason, attrs);
        }

        static AttributeSet emptyAttributes() {
            return new TestAttributeSet(List.of());
        }

        private static EncodedObject minimalEncodedObject() {
            return new EncodedObject(Encoding.DER, new byte[] { 0x01, 0x02, 0x03 });
        }

        private static String nextSeq() {
            return String.format("%016x", Long.valueOf(SEQ.getAndIncrement()));
        }
    }
}
