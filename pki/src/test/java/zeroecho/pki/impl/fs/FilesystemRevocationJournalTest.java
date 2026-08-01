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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.Util;
import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.credential.EffectiveCredentialStatus;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.StoreBackedEffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

final class FilesystemRevocationJournalTest {
    private static final int CODEC_MAGIC = 0x5A454346;
    private static final int CODEC_VERSION = 2;
    private static final int TOP_REVOCATION = 4;
    private static final int TYPE_STRING = 1;
    private static final int TYPE_LONG = 3;
    private static final int TYPE_INSTANT = 5;
    private static final int TYPE_LIST = 7;
    private static final int TYPE_OPTIONAL = 8;
    private static final int TYPE_PKI_ID = 20;
    private static final int TYPE_ATTRIBUTE_SET = 31;
    private static final int TYPE_REVOCATION_REASON = 54;
    private static final int TYPE_REVOCATION_STATE = 60;
    private static final int TYPE_REVOCATION_TRANSITION = 61;
    private static final Instant TIME = Instant.parse("2026-07-01T12:00:00Z");
    private static final AttributeId NOTE = new AttributeId("test.note");

    @TempDir
    private Path temporaryDirectory;

    @Test
    void legalTransitionsAreContiguousDurableAndPermanentIsTerminal() throws Exception {
        Path root = temporaryDirectory.resolve("legal");
        Credential credential = credential("legal");
        try (FilesystemPkiStore store = store(root)) {
            store.putCredential(credential);
            assertTransition(store, hold(credential), 1L, RevocationState.HELD);
            assertTransition(store, unhold(credential), 2L, RevocationState.CLEAR);
            assertTransition(store, hold(credential), 3L, RevocationState.HELD);
            assertTransition(store, revoke(credential, RevocationReason.KEY_COMPROMISE), 4L,
                    RevocationState.PERMANENTLY_REVOKED);
            assertCode("REVOCATION_TERMINAL", () -> transition(store, unhold(credential)));
            assertCode("REVOCATION_TERMINAL",
                    () -> transition(store, revoke(credential, RevocationReason.CA_COMPROMISE)));
        }
        try (FilesystemPkiStore reopened = store(root)) {
            RevocationJournal journal = reopened.getRevocationJournal(credential.credentialId()).orElseThrow();
            assertEquals(4, journal.transitions().size());
            assertEquals(RevocationState.PERMANENTLY_REVOKED, journal.latest().state());
            assertEquals(RevocationReason.KEY_COMPROMISE, journal.latest().permanentReason().orElseThrow());
        }
    }

    @Test
    void everyLegalPermanentTransitionIsAccepted() throws Exception {
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("legal-permanent"))) {
            Credential direct = credential("permanent-from-none");
            Credential fromClear = credential("permanent-from-clear");
            Credential fromHeld = credential("permanent-from-held");
            store.putCredential(direct);
            store.putCredential(fromClear);
            store.putCredential(fromHeld);

            RevocationJournal directJournal = transition(store, revoke(direct, RevocationReason.KEY_COMPROMISE));
            assertEquals(List.of(RevocationState.PERMANENTLY_REVOKED), states(directJournal));
            assertEquals(1L, directJournal.latest().revision());

            transition(store, hold(fromClear));
            transition(store, unhold(fromClear));
            RevocationJournal clearJournal = transition(store, revoke(fromClear, RevocationReason.CA_COMPROMISE));
            assertEquals(List.of(RevocationState.HELD, RevocationState.CLEAR, RevocationState.PERMANENTLY_REVOKED),
                    states(clearJournal));
            assertEquals(3L, clearJournal.latest().revision());

            transition(store, hold(fromHeld));
            RevocationJournal heldJournal = transition(store, revoke(fromHeld, RevocationReason.SUPERSEDED));
            assertEquals(List.of(RevocationState.HELD, RevocationState.PERMANENTLY_REVOKED), states(heldJournal));
            assertEquals(2L, heldJournal.latest().revision());
        }
    }

    @Test
    void illegalAndInvalidCommandsFailBeforeJournalMutation() throws Exception {
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("illegal"))) {
            Credential unknown = credential("unknown");
            assertCode("REVOCATION_CREDENTIAL_NOT_FOUND", () -> transition(store, hold(unknown)));

            Credential credential = credential("known");
            store.putCredential(credential);
            assertCode("REVOCATION_TRANSITION_ILLEGAL", () -> transition(store, unhold(credential)));
            assertThrows(IllegalArgumentException.class, () -> revoke(credential, RevocationReason.CERTIFICATE_HOLD));
            assertTrue(store.getRevocationJournal(credential.credentialId()).isEmpty());

            transition(store, hold(credential));
            assertCode("REVOCATION_TRANSITION_ILLEGAL", () -> transition(store, hold(credential)));
            assertEquals(1, store.getRevocationJournal(credential.credentialId()).orElseThrow().transitions().size());

            transition(store, unhold(credential));
            Path journalPath = new FsPaths(temporaryDirectory.resolve("illegal"))
                    .revocationJournal(credential.credentialId());
            byte[] clearBytes = FsOperations.readAll(journalPath);
            assertCode("REVOCATION_TRANSITION_ILLEGAL", () -> transition(store, unhold(credential)));
            assertArrayEquals(clearBytes, FsOperations.readAll(journalPath));

            transition(store, revoke(credential, RevocationReason.KEY_COMPROMISE));
            byte[] permanentBytes = FsOperations.readAll(journalPath);
            assertCode("REVOCATION_TERMINAL", () -> transition(store, hold(credential)));
            assertCode("REVOCATION_TERMINAL",
                    () -> transition(store, revoke(credential, RevocationReason.KEY_COMPROMISE)));
            assertCode("REVOCATION_TERMINAL",
                    () -> transition(store, revoke(credential, RevocationReason.CA_COMPROMISE)));
            assertArrayEquals(permanentBytes, FsOperations.readAll(journalPath));

            Credential invalidRemove = credential("invalid-remove");
            store.putCredential(invalidRemove);
            assertThrows(IllegalArgumentException.class, () -> revoke(invalidRemove, RevocationReason.REMOVE_FROM_CRL));
            assertTrue(store.getRevocationJournal(invalidRemove.credentialId()).isEmpty());
        }
    }

    @Test
    void sameCredentialConcurrentHoldHasExactlyOneCommittedWinner() throws Exception {
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("concurrent"))) {
            Credential credential = credential("concurrent");
            store.putCredential(credential);
            CyclicBarrier barrier = new CyclicBarrier(2);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                CompletableFuture<Boolean> first = attemptHold(store, credential, barrier, executor);
                CompletableFuture<Boolean> second = attemptHold(store, credential, barrier, executor);
                assertEquals(1L, List.of(first.join(), second.join()).stream().filter(Boolean::booleanValue).count());
            } finally {
                executor.shutdownNow();
            }
            RevocationJournal journal = store.getRevocationJournal(credential.credentialId()).orElseThrow();
            assertEquals(1, journal.transitions().size());
            assertEquals(1L, journal.latest().revision());
        }
    }

    @Test
    void conflictingTransitionsSerializeWithoutLostUpdates() throws Exception {
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("concurrent-conflicts"))) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Credential fromNone = credential("hold-vs-permanent");
                store.putCredential(fromNone);
                runConcurrent(store, hold(fromNone), revoke(fromNone, RevocationReason.KEY_COMPROMISE), executor);
                RevocationJournal fromNoneJournal = store.getRevocationJournal(fromNone.credentialId()).orElseThrow();
                assertEquals(RevocationState.PERMANENTLY_REVOKED, fromNoneJournal.latest().state());
                assertTrue(fromNoneJournal.transitions().size() == 1 || fromNoneJournal.transitions().size() == 2);

                Credential fromHeld = credential("unhold-vs-permanent");
                store.putCredential(fromHeld);
                transition(store, hold(fromHeld));
                runConcurrent(store, unhold(fromHeld), revoke(fromHeld, RevocationReason.CA_COMPROMISE), executor);
                RevocationJournal fromHeldJournal = store.getRevocationJournal(fromHeld.credentialId()).orElseThrow();
                assertEquals(RevocationState.PERMANENTLY_REVOKED, fromHeldJournal.latest().state());
                assertTrue(fromHeldJournal.transitions().size() == 2 || fromHeldJournal.transitions().size() == 3);

                Credential reasons = credential("competing-permanent-reasons");
                store.putCredential(reasons);
                List<Boolean> results = runConcurrent(store, revoke(reasons, RevocationReason.KEY_COMPROMISE),
                        revoke(reasons, RevocationReason.CA_COMPROMISE), executor);
                assertEquals(1L, results.stream().filter(Boolean::booleanValue).count());
                RevocationJournal reasonsJournal = store.getRevocationJournal(reasons.credentialId()).orElseThrow();
                assertEquals(1, reasonsJournal.transitions().size());
                assertTrue(reasonsJournal.latest().permanentReason().filter(
                        reason -> reason == RevocationReason.KEY_COMPROMISE || reason == RevocationReason.CA_COMPROMISE)
                        .isPresent());
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void unrelatedCredentialTransitionProgressesWhileAnotherCredentialLockIsHeld() throws Exception {
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("independent-locks"))) {
            Credential blocked = credential("blocked");
            Credential independent = credential("independent");
            store.putCredential(blocked);
            store.putCredential(independent);

            Method acquire = FilesystemPkiStore.class.getDeclaredMethod("acquireRevocationLock", PkiId.class);
            Method release = Arrays.stream(FilesystemPkiStore.class.getDeclaredMethods())
                    .filter(method -> method.getName().equals("releaseRevocationLock")).findFirst().orElseThrow();
            acquire.setAccessible(true);
            release.setAccessible(true);
            Object heldLock = acquire.invoke(store, blocked.credentialId());
            ExecutorService executor = Executors.newFixedThreadPool(2);
            CountDownLatch blockedStarted = new CountDownLatch(1);
            try {
                CompletableFuture<RevocationJournal> blockedTransition = CompletableFuture.supplyAsync(() -> {
                    blockedStarted.countDown();
                    return transition(store, hold(blocked));
                }, executor);
                assertTrue(blockedStarted.await(5, TimeUnit.SECONDS));
                CompletableFuture<RevocationJournal> independentTransition = CompletableFuture
                        .supplyAsync(() -> transition(store, hold(independent)), executor);
                assertEquals(RevocationState.HELD, independentTransition.get(5, TimeUnit.SECONDS).latest().state());
                assertFalse(blockedTransition.isDone());
                release.invoke(store, blocked.credentialId(), heldLock);
                heldLock = null;
                assertEquals(RevocationState.HELD, blockedTransition.get(5, TimeUnit.SECONDS).latest().state());
            } finally {
                if (heldLock != null) {
                    release.invoke(store, blocked.credentialId(), heldLock);
                }
                executor.shutdownNow();
            }
        }
    }

    @Test
    void copiedNamespaceJournalAndRegressingTransitionTimeFailClosed() throws Exception {
        Path root = temporaryDirectory.resolve("corrupt");
        Credential credential = credential("corrupt");
        try (FilesystemPkiStore store = store(root)) {
            store.putCredential(credential);
            transition(store, hold(credential));
            assertCode("REVOCATION_TRANSITION_CONFLICT",
                    () -> store.transitionRevocation(unhold(credential), TIME.minusSeconds(1)));

            RevocationJournal invalid = new RevocationJournal(new PkiId("credential:copied"),
                    List.of(new RevocationTransition(1L, RevocationState.HELD, TIME, Optional.empty(),
                            new SimpleAttributeSet())));
            FsOperations.writeAtomic(new FsPaths(root).revocationJournal(credential.credentialId()),
                    FsCodec.encode(FsCodec.REVOCATION_JOURNAL, invalid));
            assertCode("REVOCATION_STATE_CORRUPT", () -> store.getRevocationJournal(credential.credentialId()));
        }
    }

    @Test
    void transitionMetadataDefensivelySnapshotsByteValues() {
        byte[] source = { 1, 2, 3 };
        AttributeSet attributes = SimpleAttributeSet.builder().put(NOTE, new AttributeValue.BytesValue(source)).build();
        RevocationTransition transition = new RevocationTransition(1L, RevocationState.HELD, TIME, Optional.empty(),
                attributes);
        source[0] = 9;
        byte[] first = ((AttributeValue.BytesValue) transition.attributes().get(NOTE).orElseThrow()).value();
        assertArrayEquals(new byte[] { 1, 2, 3 }, first);
        first[1] = 9;
        byte[] second = ((AttributeValue.BytesValue) transition.attributes().get(NOTE).orElseThrow()).value();
        assertArrayEquals(new byte[] { 1, 2, 3 }, second);
    }

    @Test
    void journalConstructorRejectsEveryHostileSequenceShape() {
        PkiId id = new PkiId("credential:hostile");
        SimpleAttributeSet attributes = new SimpleAttributeSet();
        assertThrows(IllegalArgumentException.class, () -> new RevocationJournal(id,
                List.of(new RevocationTransition(1L, RevocationState.CLEAR, TIME, Optional.empty(), attributes))));
        assertThrows(IllegalArgumentException.class, () -> new RevocationJournal(id,
                List.of(new RevocationTransition(2L, RevocationState.HELD, TIME, Optional.empty(), attributes))));
        assertThrows(IllegalArgumentException.class,
                () -> new RevocationJournal(id,
                        List.of(new RevocationTransition(1L, RevocationState.HELD, TIME, Optional.empty(), attributes),
                                new RevocationTransition(2L, RevocationState.CLEAR, TIME.minusNanos(1),
                                        Optional.empty(), attributes))));
        assertThrows(IllegalArgumentException.class,
                () -> new RevocationJournal(id,
                        List.of(new RevocationTransition(1L, RevocationState.PERMANENTLY_REVOKED, TIME,
                                Optional.of(RevocationReason.CERTIFICATE_HOLD), attributes))));
        assertThrows(IllegalArgumentException.class,
                () -> new RevocationJournal(id, List.of(
                        new RevocationTransition(1L, RevocationState.PERMANENTLY_REVOKED, TIME,
                                Optional.of(RevocationReason.KEY_COMPROMISE), attributes),
                        new RevocationTransition(2L, RevocationState.HELD, TIME, Optional.empty(), attributes))));
    }

    @TestFactory
    Stream<DynamicTest> strictCodecCorruptionFailsReadAndTransitionWithoutOverwrite() {
        return Arrays.stream(CorruptionCase.values()).map(corruption -> DynamicTest.dynamicTest(corruption.description,
                () -> assertPersistedCorruptionRejected(corruption)));
    }

    @Test
    void obsoleteCurrentAndHistoryLayoutCannotInfluenceTrustedJournalOrResolver() throws Exception {
        Path root = temporaryDirectory.resolve("obsolete-layout");
        Credential credential = credential("obsolete-layout");
        try (FilesystemPkiStore store = store(root)) {
            store.putCredential(credential);
        }
        Path legacyDirectory = new FsPaths(root).revocationDir(credential.credentialId());
        FsOperations.ensureDir(legacyDirectory.resolve("history"));
        FsOperations.writeAtomic(legacyDirectory.resolve("current.bin"),
                oldRevokedRecordPayload(credential.credentialId()));
        FsOperations.writeAtomic(legacyDirectory.resolve("history").resolve("legacy.bin"),
                oldRevokedRecordPayload(credential.credentialId()));

        try (FilesystemPkiStore reopened = store(root)) {
            assertTrue(reopened.getRevocationJournal(credential.credentialId()).isEmpty());
            StoreBackedEffectiveCredentialStatusResolver resolver = new StoreBackedEffectiveCredentialStatusResolver(
                    reopened, Clock.fixed(TIME, java.time.ZoneOffset.UTC));
            assertEquals(EffectiveCredentialStatus.USABLE, resolver.beginEvaluation()
                    .resolve(reopened.getCredential(credential.credentialId()).orElseThrow()));
            transition(reopened, hold(credential));
            assertEquals(RevocationState.HELD,
                    reopened.getRevocationJournal(credential.credentialId()).orElseThrow().latest().state());
        }
    }

    @Test
    void durabilityUncertaintyMakesEveryStoreOperationFailClosed() throws Exception {
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("uncertain"))) {
            Credential credential = credential("uncertain");
            store.putCredential(credential);
            Field field = FilesystemPkiStore.class.getDeclaredField("durabilityUncertain");
            field.setAccessible(true);
            ((AtomicBoolean) field.get(store)).set(true);

            assertCode("STORE_DURABILITY_UNCONFIRMED", () -> store.getCredential(credential.credentialId()));
            assertCode("STORE_DURABILITY_UNCONFIRMED", store::listCas);
            assertCode("STORE_DURABILITY_UNCONFIRMED", store::signingNow);
        }
    }

    private static CompletableFuture<Boolean> attemptHold(FilesystemPkiStore store, Credential credential,
            CyclicBarrier barrier, ExecutorService executor) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                barrier.await();
                transition(store, hold(credential));
                return true;
            } catch (PkiException expected) {
                assertTrue(expected.getMessage().contains("REVOCATION_TRANSITION_ILLEGAL"));
                return false;
            } catch (Exception unexpected) {
                throw new IllegalStateException(unexpected);
            }
        }, executor);
    }

    private static List<Boolean> runConcurrent(FilesystemPkiStore store, RevocationCommand firstCommand,
            RevocationCommand secondCommand, ExecutorService executor) {
        CyclicBarrier barrier = new CyclicBarrier(2);
        CompletableFuture<Boolean> first = attemptTransition(store, firstCommand, barrier, executor);
        CompletableFuture<Boolean> second = attemptTransition(store, secondCommand, barrier, executor);
        return List.of(first.join(), second.join());
    }

    private static CompletableFuture<Boolean> attemptTransition(FilesystemPkiStore store, RevocationCommand command,
            CyclicBarrier barrier, ExecutorService executor) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                barrier.await();
                transition(store, command);
                return true;
            } catch (PkiException expected) {
                assertTrue(expected.getMessage().contains("code=REVOCATION_TERMINAL")
                        || expected.getMessage().contains("code=REVOCATION_TRANSITION_ILLEGAL"));
                return false;
            } catch (Exception unexpected) {
                throw new IllegalStateException(unexpected);
            }
        }, executor);
    }

    private void assertPersistedCorruptionRejected(CorruptionCase corruption) throws Exception {
        String suffix = "corrupt-" + corruption.name().toLowerCase(java.util.Locale.ROOT);
        Path root = temporaryDirectory.resolve(suffix);
        Credential credential = credential(suffix);
        Path journalPath;
        byte[] corrupt;
        try (FilesystemPkiStore store = store(root)) {
            store.putCredential(credential);
            journalPath = new FsPaths(root).revocationJournal(credential.credentialId());
            corrupt = corruption.bytes(credential.credentialId());
            FsOperations.writeAtomic(journalPath, corrupt);
        }

        try (FilesystemPkiStore reopened = store(root)) {
            byte[] before = FsOperations.readAll(journalPath);
            assertCode("REVOCATION_STATE_CORRUPT", () -> reopened.getRevocationJournal(credential.credentialId()));
            assertCode("REVOCATION_STATE_CORRUPT", () -> transition(reopened, hold(credential)));
            assertArrayEquals(before, FsOperations.readAll(journalPath));
        }
    }

    private static List<RevocationState> states(RevocationJournal journal) {
        return journal.transitions().stream().map(RevocationTransition::state).toList();
    }

    private static void assertTransition(FilesystemPkiStore store, RevocationCommand command, long revision,
            RevocationState state) {
        RevocationJournal journal = transition(store, command);
        assertEquals(revision, journal.latest().revision());
        assertEquals(state, journal.latest().state());
    }

    private static RevocationJournal transition(FilesystemPkiStore store, RevocationCommand command) {
        return store.transitionRevocation(command, TIME);
    }

    private static RevocationCommand.Hold hold(Credential credential) {
        return new RevocationCommand.Hold(credential.credentialId(), new SimpleAttributeSet());
    }

    private static RevocationCommand.Unhold unhold(Credential credential) {
        return new RevocationCommand.Unhold(credential.credentialId(), new SimpleAttributeSet());
    }

    private static RevocationCommand.RevokePermanently revoke(Credential credential, RevocationReason reason) {
        return new RevocationCommand.RevokePermanently(credential.credentialId(), reason, new SimpleAttributeSet());
    }

    private static void assertCode(String code, Runnable operation) {
        PkiException failure = assertThrows(PkiException.class, operation::run);
        assertTrue(failure.getMessage().contains("code=" + code));
    }

    private static FilesystemPkiStore store(Path root) {
        return new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
    }

    private Credential credential(String suffix) {
        return new Credential(new PkiId("credential:" + suffix), new FormatId("x509"),
                new IssuerRef(new PkiId("ca:issuer")), new SubjectRef("CN=" + suffix),
                new Validity(TIME.minusSeconds(60), TIME.plusSeconds(60)), suffix, new PkiId("key:" + suffix),
                new CaProfileBinding(new zeroecho.pki.api.profile.CertificateProfileRef("default", 1, new byte[32])),
                CredentialStatus.ISSUED,
                fixtureReference(),
                new SimpleAttributeSet());
    }

    private zeroecho.pki.api.content.DurableContentReference fixtureReference() {
        try {
            FilesystemStagedContentStore staged = new FilesystemStagedContentStore(
                    temporaryDirectory.resolve("reference-fixtures"), "0123456789abcdef0123456789abcdef");
            return zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(staged, Encoding.DER,
                    new byte[] { 1, 2, 3 });
        } catch (IOException exception) {
            throw new AssertionError("Unable to stage credential fixture", exception);
        }
    }

    private static byte[] journalPayload(PkiId credentialId, long journalVersion, RawTransition... transitions)
            throws IOException {
        ByteArrayOutputStream output = envelope();
        writePkiId(output, credentialId);
        writeTypedLong(output, journalVersion);
        output.write(TYPE_LIST);
        output.write(TYPE_REVOCATION_TRANSITION);
        Util.writePack7I(output, transitions.length);
        for (RawTransition transition : transitions) {
            output.write(TYPE_REVOCATION_TRANSITION);
            writeTypedLong(output, transition.revision);
            output.write(TYPE_REVOCATION_STATE);
            output.write(stateCode(transition.state));
            output.write(TYPE_INSTANT);
            Util.writeLong(output, transition.time.getEpochSecond());
            Util.writePack7I(output, transition.time.getNano());
            output.write(TYPE_OPTIONAL);
            output.write(TYPE_REVOCATION_REASON);
            if (transition.reason.isPresent()) {
                output.write(1);
                output.write(TYPE_REVOCATION_REASON);
                output.write(reasonCode(transition.reason.orElseThrow()));
            } else {
                output.write(0);
            }
            output.write(TYPE_ATTRIBUTE_SET);
            Util.writePack7I(output, 0);
        }
        return output.toByteArray();
    }

    private static byte[] oldRevokedRecordPayload(PkiId credentialId) throws IOException {
        ByteArrayOutputStream output = envelope();
        writePkiId(output, credentialId);
        output.write(TYPE_INSTANT);
        Util.writeLong(output, TIME.getEpochSecond());
        Util.writePack7I(output, TIME.getNano());
        output.write(TYPE_REVOCATION_REASON);
        output.write(reasonCode(RevocationReason.KEY_COMPROMISE));
        output.write(TYPE_ATTRIBUTE_SET);
        Util.writePack7I(output, 0);
        return output.toByteArray();
    }

    private static ByteArrayOutputStream envelope() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        output.write(CODEC_MAGIC >>> 24);
        output.write(CODEC_MAGIC >>> 16);
        output.write(CODEC_MAGIC >>> 8);
        output.write(CODEC_MAGIC);
        output.write(CODEC_VERSION);
        output.write(TOP_REVOCATION);
        return output;
    }

    private static void writePkiId(ByteArrayOutputStream output, PkiId id) throws IOException {
        output.write(TYPE_PKI_ID);
        output.write(TYPE_STRING);
        Util.writeUTF8(output, id.value());
    }

    private static void writeTypedLong(ByteArrayOutputStream output, long value) throws IOException {
        output.write(TYPE_LONG);
        Util.writeLong(output, value);
    }

    private static int stateCode(RevocationState state) {
        return switch (state) {
            case CLEAR -> 1;
            case HELD -> 2;
            case PERMANENTLY_REVOKED -> 3;
        };
    }

    private static int reasonCode(RevocationReason reason) {
        return switch (reason) {
            case UNSPECIFIED -> 1;
            case KEY_COMPROMISE -> 2;
            case CA_COMPROMISE -> 3;
            case AFFILIATION_CHANGED -> 4;
            case SUPERSEDED -> 5;
            case CESSATION_OF_OPERATION -> 6;
            case CERTIFICATE_HOLD -> 7;
            case REMOVE_FROM_CRL -> 8;
            case PRIVILEGE_WITHDRAWN -> 9;
            case AA_COMPROMISE -> 10;
        };
    }

    private record RawTransition(long revision, RevocationState state, Instant time,
            Optional<RevocationReason> reason) {
    }

    private enum CorruptionCase {
        ZERO_TRANSITIONS("zero transitions"), ZERO_REVISION("zero transition revision"),
        FIRST_REVISION_NOT_ONE("first revision is not one"), REVISION_GAP("revision gap"),
        DUPLICATE_REVISION("duplicate revision"), BACKWARD_TIME("backward transition time"),
        CLEAR_FIRST("CLEAR as first state"), CLEAR_NOT_AFTER_HELD("CLEAR not immediately after HELD"),
        REPEATED_HELD("repeated HELD"), PERMANENT_REASON_MISSING("permanent revocation without reason"),
        PERMANENT_REASON_CERTIFICATE_HOLD("permanent revocation with hold reason"),
        PERMANENT_REASON_REMOVE_FROM_CRL("permanent revocation with remove-from-CRL reason"),
        HELD_WITH_REASON("HELD with permanent reason"), CLEAR_WITH_REASON("CLEAR with permanent reason"),
        TRANSITION_AFTER_PERMANENT("transition after permanent revocation"),
        MISMATCHED_CREDENTIAL_ID("mismatched credential namespace"),
        UNSUPPORTED_JOURNAL_VERSION("unsupported embedded journal version"),
        OLD_REVOKED_RECORD_PAYLOAD("old RevokedRecord payload"), TRUNCATED_PAYLOAD("truncated current journal"),
        TRAILING_PAYLOAD("trailing journal data");

        private final String description;

        CorruptionCase(String description) {
            this.description = description;
        }

        private byte[] bytes(PkiId credentialId) throws IOException {
            RawTransition held = raw(1L, RevocationState.HELD, TIME);
            return switch (this) {
                case ZERO_TRANSITIONS -> journalPayload(credentialId, 1L);
                case ZERO_REVISION -> journalPayload(credentialId, 1L, raw(0L, RevocationState.HELD, TIME));
                case FIRST_REVISION_NOT_ONE -> journalPayload(credentialId, 1L, raw(2L, RevocationState.HELD, TIME));
                case REVISION_GAP ->
                    journalPayload(credentialId, 1L, held, raw(3L, RevocationState.CLEAR, TIME.plusSeconds(1)));
                case DUPLICATE_REVISION ->
                    journalPayload(credentialId, 1L, held, raw(1L, RevocationState.CLEAR, TIME.plusSeconds(1)));
                case BACKWARD_TIME ->
                    journalPayload(credentialId, 1L, held, raw(2L, RevocationState.CLEAR, TIME.minusSeconds(1)));
                case CLEAR_FIRST -> journalPayload(credentialId, 1L, raw(1L, RevocationState.CLEAR, TIME));
                case CLEAR_NOT_AFTER_HELD ->
                    journalPayload(credentialId, 1L, held, raw(2L, RevocationState.CLEAR, TIME.plusSeconds(1)),
                            raw(3L, RevocationState.CLEAR, TIME.plusSeconds(2)));
                case REPEATED_HELD ->
                    journalPayload(credentialId, 1L, held, raw(2L, RevocationState.HELD, TIME.plusSeconds(1)));
                case PERMANENT_REASON_MISSING ->
                    journalPayload(credentialId, 1L, raw(1L, RevocationState.PERMANENTLY_REVOKED, TIME));
                case PERMANENT_REASON_CERTIFICATE_HOLD -> journalPayload(credentialId, 1L,
                        raw(1L, RevocationState.PERMANENTLY_REVOKED, TIME, RevocationReason.CERTIFICATE_HOLD));
                case PERMANENT_REASON_REMOVE_FROM_CRL -> journalPayload(credentialId, 1L,
                        raw(1L, RevocationState.PERMANENTLY_REVOKED, TIME, RevocationReason.REMOVE_FROM_CRL));
                case HELD_WITH_REASON -> journalPayload(credentialId, 1L,
                        raw(1L, RevocationState.HELD, TIME, RevocationReason.KEY_COMPROMISE));
                case CLEAR_WITH_REASON -> journalPayload(credentialId, 1L, held,
                        raw(2L, RevocationState.CLEAR, TIME.plusSeconds(1), RevocationReason.KEY_COMPROMISE));
                case TRANSITION_AFTER_PERMANENT -> journalPayload(credentialId, 1L,
                        raw(1L, RevocationState.PERMANENTLY_REVOKED, TIME, RevocationReason.KEY_COMPROMISE),
                        raw(2L, RevocationState.HELD, TIME.plusSeconds(1)));
                case MISMATCHED_CREDENTIAL_ID -> journalPayload(new PkiId("credential:other-namespace"), 1L, held);
                case UNSUPPORTED_JOURNAL_VERSION -> journalPayload(credentialId, 2L, held);
                case OLD_REVOKED_RECORD_PAYLOAD -> oldRevokedRecordPayload(credentialId);
                case TRUNCATED_PAYLOAD -> {
                    byte[] valid = journalPayload(credentialId, 1L, held);
                    yield Arrays.copyOf(valid, valid.length - 1);
                }
                case TRAILING_PAYLOAD -> {
                    byte[] valid = journalPayload(credentialId, 1L, held);
                    yield Arrays.copyOf(valid, valid.length + 1);
                }
            };
        }

        private static RawTransition raw(long revision, RevocationState state, Instant time) {
            return new RawTransition(revision, state, time, Optional.empty());
        }

        private static RawTransition raw(long revision, RevocationState state, Instant time, RevocationReason reason) {
            return new RawTransition(revision, state, time, Optional.of(reason));
        }
    }
}
