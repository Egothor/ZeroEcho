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

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

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
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.application.RevocationExecutionEvidence;
import zeroecho.pki.impl.core.StoreBackedEffectiveCredentialStatusResolver;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;

final class FilesystemRevocationAuthorityTest {
    private static final Instant TIME = Instant.parse("2026-07-01T12:00:00Z");
    private static final AttributeId NOTE = new AttributeId("test.note");

    @TempDir
    private Path temporaryDirectory;

    @Test
    void legalTransitionsAreContiguousDurableAndPermanentIsTerminal() throws Exception {
        System.out.println("legalTransitionsAreContiguousDurableAndPermanentIsTerminal");
        Path root = temporaryDirectory.resolve("legal");
        Credential credential;
        try (FilesystemPkiStore store = store(root)) {
            credential = credential(store, "legal");
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
            CredentialHistory history = readHistory(reopened, credential.credentialId()).orElseThrow();
            assertEquals(4, history.transitions().size());
            assertEquals(RevocationState.PERMANENTLY_REVOKED, history.latest().state());
            assertEquals(RevocationReason.KEY_COMPROMISE, history.latest().permanentReason().orElseThrow());
        }
        System.out.println("legalTransitionsAreContiguousDurableAndPermanentIsTerminal...ok");
    }

    @Test
    void authoritativeEvidenceAndNativeFieldsSurviveHistoryReopen() throws Exception {
        Path root = temporaryDirectory.resolve("evidence-reopen");
        Credential credential;
        RevocationExecutionEvidence evidence = RevocationExecutionEvidence.administrative("operator-a", "realm-a",
                "request-a", RevocationExecutionEvidence.Authentication.DIRECT_MTLS,
                RevocationExecutionEvidence.AuthorizationPath.APPROVAL, "a".repeat(64),
                Optional.of("ticket-100"));
        try (FilesystemPkiStore store = store(root)) {
            credential = credential(store, "evidence-reopen");
            store.putCredential(credential);
            transition(store, new RevocationCommand.RevokePermanently(credential.credentialId(),
                    RevocationReason.KEY_COMPROMISE, evidence.attributes()));
        }
        try (FilesystemPkiStore reopened = store(root)) {
            RevocationTransition transition = readHistory(reopened, credential.credentialId()).orElseThrow().latest();
            assertEquals(1L, transition.revision());
            assertEquals(TIME, transition.time());
            assertEquals(RevocationState.PERMANENTLY_REVOKED, transition.state());
            assertEquals(RevocationReason.KEY_COMPROMISE, transition.permanentReason().orElseThrow());
            assertEquals(evidence.attributes().ids(), transition.attributes().ids());
            for (AttributeId id : evidence.attributes().ids()) {
                assertEquals(evidence.attributes().getAll(id), transition.attributes().getAll(id));
            }
        }
    }

    @Test
    void everyLegalPermanentTransitionIsAccepted() throws Exception {
        System.out.println("everyLegalPermanentTransitionIsAccepted");
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("legal-permanent"))) {
            Credential direct = credential(store, "permanent-from-none");
            Credential fromClear = credential(store, "permanent-from-clear");
            Credential fromHeld = credential(store, "permanent-from-held");
            store.putCredential(direct);
            store.putCredential(fromClear);
            store.putCredential(fromHeld);

            CredentialHistory directHistory = transition(store, revoke(direct, RevocationReason.KEY_COMPROMISE));
            assertEquals(List.of(RevocationState.PERMANENTLY_REVOKED), states(directHistory));
            assertEquals(1L, directHistory.latest().revision());

            transition(store, hold(fromClear));
            transition(store, unhold(fromClear));
            CredentialHistory clearHistory = transition(store, revoke(fromClear, RevocationReason.CA_COMPROMISE));
            assertEquals(List.of(RevocationState.HELD, RevocationState.CLEAR, RevocationState.PERMANENTLY_REVOKED),
                    states(clearHistory));
            assertEquals(3L, clearHistory.latest().revision());

            transition(store, hold(fromHeld));
            CredentialHistory heldHistory = transition(store, revoke(fromHeld, RevocationReason.SUPERSEDED));
            assertEquals(List.of(RevocationState.HELD, RevocationState.PERMANENTLY_REVOKED), states(heldHistory));
            assertEquals(2L, heldHistory.latest().revision());
        }
        System.out.println("everyLegalPermanentTransitionIsAccepted...ok");
    }

    @Test
    void illegalAndInvalidCommandsFailBeforeHistoryMutation() throws Exception {
        System.out.println("illegalAndInvalidCommandsFailBeforeHistoryMutation");
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("illegal"))) {
            Credential unknown = credential(store, "unknown");
            assertCode("REVOCATION_CREDENTIAL_NOT_FOUND", () -> transition(store, hold(unknown)));

            Credential credential = credential(store, "known");
            store.putCredential(credential);
            assertCode("REVOCATION_TRANSITION_ILLEGAL", () -> transition(store, unhold(credential)));
            assertThrows(IllegalArgumentException.class, () -> revoke(credential, RevocationReason.CERTIFICATE_HOLD));
            assertTrue(readHistory(store, credential.credentialId()).isEmpty());

            transition(store, hold(credential));
            assertCode("REVOCATION_TRANSITION_ILLEGAL", () -> transition(store, hold(credential)));
            assertEquals(1, readHistory(store, credential.credentialId()).orElseThrow().transitions().size());

            transition(store, unhold(credential));
            Path logPath = new FsPaths(temporaryDirectory.resolve("illegal")).revocationTransitionLog();
            byte[] clearBytes = FsOperations.readAll(logPath);
            assertCode("REVOCATION_TRANSITION_ILLEGAL", () -> transition(store, unhold(credential)));
            assertArrayEquals(clearBytes, FsOperations.readAll(logPath));

            transition(store, revoke(credential, RevocationReason.KEY_COMPROMISE));
            byte[] permanentBytes = FsOperations.readAll(logPath);
            assertCode("REVOCATION_TERMINAL", () -> transition(store, hold(credential)));
            assertCode("REVOCATION_TERMINAL",
                    () -> transition(store, revoke(credential, RevocationReason.KEY_COMPROMISE)));
            assertCode("REVOCATION_TERMINAL",
                    () -> transition(store, revoke(credential, RevocationReason.CA_COMPROMISE)));
            assertArrayEquals(permanentBytes, FsOperations.readAll(logPath));

            Credential invalidRemove = credential(store, "invalid-remove");
            store.putCredential(invalidRemove);
            assertThrows(IllegalArgumentException.class, () -> revoke(invalidRemove, RevocationReason.REMOVE_FROM_CRL));
            assertTrue(readHistory(store, invalidRemove.credentialId()).isEmpty());
        }
        System.out.println("illegalAndInvalidCommandsFailBeforeHistoryMutation...ok");
    }

    @Test
    void sameCredentialConcurrentHoldHasExactlyOneCommittedWinner() throws Exception {
        System.out.println("sameCredentialConcurrentHoldHasExactlyOneCommittedWinner");
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("concurrent"))) {
            Credential credential = credential(store, "concurrent");
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
            CredentialHistory history = readHistory(store, credential.credentialId()).orElseThrow();
            assertEquals(1, history.transitions().size());
            assertEquals(1L, history.latest().revision());
        }
        System.out.println("sameCredentialConcurrentHoldHasExactlyOneCommittedWinner...ok");
    }

    @Test
    void conflictingTransitionsSerializeWithoutLostUpdates() throws Exception {
        System.out.println("conflictingTransitionsSerializeWithoutLostUpdates");
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("concurrent-conflicts"))) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Credential fromNone = credential(store, "hold-vs-permanent");
                store.putCredential(fromNone);
                runConcurrent(store, hold(fromNone), revoke(fromNone, RevocationReason.KEY_COMPROMISE), executor);
                CredentialHistory fromNoneHistory = readHistory(store, fromNone.credentialId()).orElseThrow();
                assertEquals(RevocationState.PERMANENTLY_REVOKED, fromNoneHistory.latest().state());
                assertTrue(fromNoneHistory.transitions().size() == 1 || fromNoneHistory.transitions().size() == 2);

                Credential fromHeld = credential(store, "unhold-vs-permanent");
                store.putCredential(fromHeld);
                transition(store, hold(fromHeld));
                runConcurrent(store, unhold(fromHeld), revoke(fromHeld, RevocationReason.CA_COMPROMISE), executor);
                CredentialHistory fromHeldHistory = readHistory(store, fromHeld.credentialId()).orElseThrow();
                assertEquals(RevocationState.PERMANENTLY_REVOKED, fromHeldHistory.latest().state());
                assertTrue(fromHeldHistory.transitions().size() == 2 || fromHeldHistory.transitions().size() == 3);

                Credential reasons = credential(store, "competing-permanent-reasons");
                store.putCredential(reasons);
                List<Boolean> results = runConcurrent(store, revoke(reasons, RevocationReason.KEY_COMPROMISE),
                        revoke(reasons, RevocationReason.CA_COMPROMISE), executor);
                assertEquals(1L, results.stream().filter(Boolean::booleanValue).count());
                CredentialHistory reasonsHistory = readHistory(store, reasons.credentialId()).orElseThrow();
                assertEquals(1, reasonsHistory.transitions().size());
                assertTrue(reasonsHistory.latest().permanentReason().filter(
                        reason -> reason == RevocationReason.KEY_COMPROMISE || reason == RevocationReason.CA_COMPROMISE)
                        .isPresent());
            } finally {
                executor.shutdownNow();
            }
        }
        System.out.println("conflictingTransitionsSerializeWithoutLostUpdates...ok");
    }

    @Test
    void unrelatedCredentialTransitionProgressesWhileAnotherCredentialLockIsHeld() throws Exception {
        System.out.println("unrelatedCredentialTransitionProgressesWhileAnotherCredentialLockIsHeld");
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("independent-locks"))) {
            Credential blocked = credential(store, "blocked");
            Credential independent = credential(store, "independent");
            store.putCredential(blocked);
            store.putCredential(independent);

            Method acquire = FilesystemPkiStore.class.getDeclaredMethod(
                    "acquireCredentialStateLock", PkiId.class);
            Method release = Arrays.stream(FilesystemPkiStore.class.getDeclaredMethods())
                    .filter(method -> method.getName().equals("releaseCredentialStateLock"))
                    .findFirst().orElseThrow();
            acquire.setAccessible(true);
            release.setAccessible(true);
            Object heldLock = acquire.invoke(store, blocked.credentialId());
            ExecutorService executor = Executors.newFixedThreadPool(2);
            CountDownLatch blockedStarted = new CountDownLatch(1);
            try {
                CompletableFuture<CredentialHistory> blockedTransition = CompletableFuture.supplyAsync(() -> {
                    blockedStarted.countDown();
                    return transition(store, hold(blocked));
                }, executor);
                assertTrue(blockedStarted.await(5, TimeUnit.SECONDS));
                CompletableFuture<CredentialHistory> independentTransition = CompletableFuture
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
        System.out.println("unrelatedCredentialTransitionProgressesWhileAnotherCredentialLockIsHeld...ok");
    }

    @Test
    void regressingTransitionTimeFailsClosed() throws Exception {
        System.out.println("regressingTransitionTimeFailsClosed");
        Path root = temporaryDirectory.resolve("corrupt");
        try (FilesystemPkiStore store = store(root)) {
            Credential credential = credential(store, "corrupt");
            store.putCredential(credential);
            transition(store, hold(credential));
            assertCode("REVOCATION_TRANSITION_CONFLICT",
                    () -> store.transitionRevocation(unhold(credential), TIME.minusSeconds(1)));

            assertEquals(RevocationState.HELD,
                    store.getRevocation(credential.credentialId()).orElseThrow().transition().state());
        }
        System.out.println("regressingTransitionTimeFailsClosed...ok");
    }

    @Test
    void transitionMetadataDefensivelySnapshotsByteValues() {
        System.out.println("transitionMetadataDefensivelySnapshotsByteValues");
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
        System.out.println("transitionMetadataDefensivelySnapshotsByteValues...ok");
    }

    @Test
    void obsoleteCurrentAndHistoryLayoutCannotInfluenceTrustedHistoryOrResolver() throws Exception {
        System.out.println("obsoleteCurrentAndHistoryLayoutCannotInfluenceTrustedHistoryOrResolver");
        Path root = temporaryDirectory.resolve("obsolete-layout");
        Path snapshot = temporaryDirectory.resolve("obsolete-layout-snapshot");
        Credential credential;
        try (FilesystemPkiStore store = store(root)) {
            credential = credential(store, "obsolete-layout");
            store.putCredential(credential);
        }
        Path legacyDirectory = root.resolve("revocations").resolve("by-credential")
                .resolve(FsUtil.safeId(credential.credentialId()));
        FsOperations.ensureDir(legacyDirectory.resolve("history"));
        FsOperations.writeAtomic(legacyDirectory.resolve("current.bin"), new byte[] { 0x01, 0x02 });
        FsOperations.writeAtomic(legacyDirectory.resolve("history").resolve("legacy.bin"),
                new byte[] { 0x03, 0x04 });
        Path legacyJournal = legacyDirectory.resolve("journal.bin");
        byte[] legacyJournalBytes = { 0x05, 0x06 };
        FsOperations.writeAtomic(legacyJournal, legacyJournalBytes);

        try (FilesystemPkiStore reopened = store(root)) {
            assertTrue(readHistory(reopened, credential.credentialId()).isEmpty());
            StoreBackedEffectiveCredentialStatusResolver resolver = new StoreBackedEffectiveCredentialStatusResolver(
                    reopened, Clock.fixed(TIME, java.time.ZoneOffset.UTC));
            assertEquals(EffectiveCredentialStatus.USABLE, resolver.beginEvaluation()
                    .resolve(reopened.getCredential(credential.credentialId()).orElseThrow()));
            transition(reopened, hold(credential));
            assertEquals(RevocationState.HELD,
                    readHistory(reopened, credential.credentialId()).orElseThrow().latest().state());
            reopened.exportSnapshot(snapshot, TIME);
        }
        assertArrayEquals(legacyJournalBytes, Files.readAllBytes(legacyJournal));
        assertFalse(Files.exists(snapshot.resolve("revocations").resolve("by-credential")));
        System.out.println("obsoleteCurrentAndHistoryLayoutCannotInfluenceTrustedHistoryOrResolver...ok");
    }

    @Test
    void unversionedLegacyJournalStoreIsRejected() throws Exception {
        System.out.println("unversionedLegacyJournalStoreIsRejected");
        Path root = temporaryDirectory.resolve("unversioned-legacy");
        Path legacyJournal = root.resolve("revocations").resolve("by-credential").resolve("credential-legacy")
                .resolve("journal.bin");
        Files.createDirectories(legacyJournal.getParent());
        Files.write(legacyJournal, new byte[] { 0x01, 0x02 });
        Path legacyCredential = root.resolve("credentials").resolve("by-id").resolve("credential-legacy.bin");
        Files.createDirectories(legacyCredential.getParent());
        Files.write(legacyCredential, new byte[] { 0x03, 0x04 });

        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> store(root));
        assertEquals("Filesystem store open failed: code=STORE_OPEN_FAILED", failure.getMessage());
        assertFalse(Files.exists(root.resolve(FsPaths.VERSION_FILE)));
        assertArrayEquals(new byte[] { 0x01, 0x02 }, Files.readAllBytes(legacyJournal));
        System.out.println("unversionedLegacyJournalStoreIsRejected...ok");
    }

    @Test
    void durabilityUncertaintyMakesEveryStoreOperationFailClosed() throws Exception {
        System.out.println("durabilityUncertaintyMakesEveryStoreOperationFailClosed");
        try (FilesystemPkiStore store = store(temporaryDirectory.resolve("uncertain"))) {
            Credential credential = credential(store, "uncertain");
            store.putCredential(credential);
            Field field = FilesystemPkiStore.class.getDeclaredField("durabilityUncertain");
            field.setAccessible(true);
            ((AtomicBoolean) field.get(store)).set(true);

            assertCode("STORE_DURABILITY_UNCONFIRMED", () -> store.getCredential(credential.credentialId()));
            assertCode("STORE_DURABILITY_UNCONFIRMED", store::listCas);
            assertCode("STORE_DURABILITY_UNCONFIRMED", store::signingNow);
        }
        System.out.println("durabilityUncertaintyMakesEveryStoreOperationFailClosed...ok");
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

    private static List<RevocationState> states(CredentialHistory history) {
        return history.transitions().stream().map(RevocationTransition::state).toList();
    }

    private static void assertTransition(FilesystemPkiStore store, RevocationCommand command, long revision,
            RevocationState state) {
        CredentialHistory history = transition(store, command);
        assertEquals(revision, history.latest().revision());
        assertEquals(state, history.latest().state());
    }

    private static CredentialHistory transition(FilesystemPkiStore store, RevocationCommand command) {
        store.transitionRevocation(command, TIME);
        return readHistory(store, command.credentialId()).orElseThrow();
    }

    private static Optional<CredentialHistory> readHistory(FilesystemPkiStore store, PkiId credentialId) {
        if (store.getRevocation(credentialId).isEmpty()) {
            return Optional.empty();
        }
        List<RevocationTransition> transitions = new ArrayList<>();
        try (zeroecho.pki.spi.store.RevocationHistory history = store.openRevocationHistory(credentialId)) {
            while (history.next()) {
                transitions.add(history.current());
            }
        } catch (IOException failure) {
            throw new IllegalStateException(failure);
        }
        return Optional.of(new CredentialHistory(credentialId, transitions));
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

    private static Credential credential(FilesystemPkiStore store, String suffix) throws IOException {
        return new Credential(new PkiId("credential:" + suffix), new FormatId("x509"),
                new IssuerRef(new PkiId("ca:issuer")), new SubjectRef("CN=" + suffix),
                new Validity(TIME.minusSeconds(60), TIME.plusSeconds(60)), suffix, new PkiId("key:" + suffix),
                new CaProfileBinding(new zeroecho.pki.api.profile.CertificateProfileRef("default", 1, new byte[32])),
                CredentialStatus.ISSUED,
                zeroecho.pki.testkit.PkiTestRuntime.stageCredential(store, new byte[] { 1, 2, 3 }),
                new SimpleAttributeSet());
    }

    private record CredentialHistory(PkiId credentialId, List<RevocationTransition> transitions) {
        private RevocationTransition latest() {
            return transitions.get(transitions.size() - 1);
        }
    }
}
