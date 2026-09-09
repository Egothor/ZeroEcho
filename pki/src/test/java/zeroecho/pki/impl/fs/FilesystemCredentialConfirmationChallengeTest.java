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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallengeIssuance;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;

class FilesystemCredentialConfirmationChallengeTest {
    private static final Clock CLOCK = Clock.fixed(Instant.EPOCH.plusSeconds(60L), ZoneOffset.UTC);
    private static final Instant ISSUED_AT = Instant.EPOCH.plusSeconds(30L);
    private static final Instant EXPIRES_AT = Instant.EPOCH.plusSeconds(40L);
    private static final ConfirmationRealmBinding REALM = new ConfirmationRealmBinding("test-realm");
    private static final String AUDIENCE = "https://pki.example.test/confirmation";
    private static final long MAXIMUM_CONFIRMATION_EPOCH_SECOND = 253_402_300_799L;

    @TempDir
    private java.nio.file.Path temporary;

    @Test
    void getsIssuesReplaysLiveRecordAndReplacesAtExactExpiry() throws Exception {
        MutableClock clock = new MutableClock(Instant.EPOCH.plusSeconds(60L));
        try (FilesystemPkiStore store = open("issue", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "issue");
            assertTrue(store.getCredentialConfirmationChallenge(lifecycle.credentialId()).isEmpty());

            clock.resetObservations();
            CredentialConfirmationChallenge initial = store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L)));
            assertEquals(Instant.EPOCH.plusSeconds(60L), initial.issuedAt());
            assertEquals(Instant.EPOCH.plusSeconds(70L), initial.expiresAt());
            assertEquals(1, clock.observations());
            assertEquals(Optional.of(initial),
                    store.getCredentialConfirmationChallenge(lifecycle.credentialId()));

            clock.set(Instant.EPOCH.plusSeconds(65L).plusNanos(999_999_999L));
            clock.resetObservations();
            CredentialConfirmationChallenge liveReplay = store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE, 8_192, 2, Duration.ofHours(1L)));
            assertEquals(initial, liveReplay);
            assertEquals(1, clock.observations());

            clock.set(Instant.EPOCH.plusSeconds(59L));
            assertThrows(IllegalStateException.class, () -> store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE, 8_192, 3, Duration.ofSeconds(10L))));

            clock.set(initial.expiresAt());
            CredentialConfirmationChallenge replacement = store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE, 8_192, 4, Duration.ofSeconds(10L)));
            assertEquals(initial.expiresAt(), replacement.issuedAt());
            assertEquals(initial.expiresAt().plusSeconds(10L), replacement.expiresAt());
            assertEquals(Optional.of(replacement),
                    store.getCredentialConfirmationChallenge(lifecycle.credentialId()));
        }
    }

    @Test
    void completesAtomicallyDeletesDerivedRecordsAndReplaysTerminalWithoutClock() throws Exception {
        MutableClock clock = new MutableClock(Instant.EPOCH.plusSeconds(60L));
        try (FilesystemPkiStore store = open("complete", clock)) {
            CredentialConfirmationLifecycle pending = pending(store, "complete");
            CredentialConfirmationChallenge challenge = store.issueCredentialConfirmationChallenge(
                    issuance(pending, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L)));
            CredentialConfirmationProofCas proof = proof(pending, challenge.recordCommitment());

            clock.resetObservations();
            CredentialConfirmationLifecycle confirmed = store.completeCredentialConfirmation(proof);
            assertEquals(1, clock.observations());
            assertEquals(Optional.of(clock.current()), confirmed.confirmedAt());
            assertEquals(Optional.of(challenge.recordCommitment()),
                    confirmed.consumedChallengeRecordCommitment());
            assertTrue(store.getCredentialConfirmationChallenge(pending.credentialId()).isEmpty());
            assertTrue(store.pagePendingCredentialConfirmationReviews(
                    store.getCredential(pending.credentialId()).orElseThrow().issuerRef().caId(),
                    Optional.empty(), pending.confirmationReviewAt(), Optional.empty(), 10)
                    .reviews().isEmpty());

            clock.set(Instant.EPOCH.plusSeconds(7_201L));
            clock.resetObservations();
            assertEquals(confirmed, store.completeCredentialConfirmation(proof));
            assertEquals(0, clock.observations());
            assertThrows(IllegalArgumentException.class, () -> store.completeCredentialConfirmation(
                    proof(pending, "3".repeat(64))));
            assertThrows(IllegalArgumentException.class, () -> store.completeCredentialConfirmation(
                    new CredentialConfirmationProofCas(pending.credentialId(), pending.revision(),
                            "4".repeat(64), challenge.recordCommitment())));
        }
    }

    @Test
    void rejectsMissingBackdatedExpiredAndRotatedChallengeWithoutPartialMutation() throws Exception {
        MutableClock clock = new MutableClock(Instant.EPOCH.plusSeconds(60L));
        try (FilesystemPkiStore store = open("completion-boundaries", clock)) {
            CredentialConfirmationLifecycle pending = pending(store, "completion-boundaries");
            CredentialConfirmationProofCas missing = proof(pending, "3".repeat(64));
            assertThrows(IllegalStateException.class,
                    () -> store.completeCredentialConfirmation(missing));

            CredentialConfirmationChallenge initial = store.issueCredentialConfirmationChallenge(
                    issuance(pending, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L)));
            CredentialConfirmationProofCas initialProof = proof(pending, initial.recordCommitment());
            clock.set(initial.issuedAt().minusSeconds(1L));
            assertThrows(IllegalStateException.class,
                    () -> store.completeCredentialConfirmation(initialProof));
            clock.set(initial.expiresAt());
            assertThrows(IllegalStateException.class,
                    () -> store.completeCredentialConfirmation(initialProof));

            CredentialConfirmationChallenge replacement = store.issueCredentialConfirmationChallenge(
                    issuance(pending, REALM, AUDIENCE, 8_192, 2, Duration.ofSeconds(10L)));
            assertThrows(IllegalArgumentException.class,
                    () -> store.completeCredentialConfirmation(initialProof));
            assertEquals(CredentialConfirmationLifecycle.State.PENDING,
                    store.getCredentialConfirmation(pending.credentialId()).orElseThrow().state());
            assertEquals(CredentialConfirmationLifecycle.State.CONFIRMED,
                    store.completeCredentialConfirmation(
                            proof(pending, replacement.recordCommitment())).state());
        }
    }

    @Test
    void rejectsCompletionAfterCredentialExpiry() throws Exception {
        MutableClock clock = new MutableClock(Instant.EPOCH.plusSeconds(60L));
        try (FilesystemPkiStore store = open("completion-expired", clock)) {
            CredentialConfirmationLifecycle pending = pending(store, "completion-expired",
                    new Validity(Instant.EPOCH, Instant.EPOCH.plusSeconds(65L)));
            CredentialConfirmationChallenge challenge = store.issueCredentialConfirmationChallenge(
                    issuance(pending, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L)));
            clock.set(Instant.EPOCH.plusSeconds(66L));

            assertThrows(IllegalStateException.class, () -> store.completeCredentialConfirmation(
                    proof(pending, challenge.recordCommitment())));
            assertEquals(CredentialConfirmationLifecycle.State.PENDING,
                    store.getCredentialConfirmation(pending.credentialId()).orElseThrow().state());
        }
    }

    @Test
    void rejectsRealmAudienceAndSuiteBindingMismatchWhileLiveAndExpired() throws Exception {
        MutableClock clock = new MutableClock(Instant.EPOCH.plusSeconds(60L));
        try (FilesystemPkiStore store = open("mismatch", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "mismatch");
            CredentialConfirmationChallenge initial = store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L)));

            for (Instant observation : List.of(Instant.EPOCH.plusSeconds(61L), initial.expiresAt())) {
                clock.set(observation);
                assertThrows(IllegalArgumentException.class,
                        () -> store.issueCredentialConfirmationChallenge(issuance(lifecycle,
                                new ConfirmationRealmBinding("other-realm"), AUDIENCE, 8_192,
                                2, Duration.ofSeconds(10L))));
                assertThrows(IllegalArgumentException.class,
                        () -> store.issueCredentialConfirmationChallenge(issuance(lifecycle,
                                REALM, "https://other.example.test/confirmation", 8_192,
                                2, Duration.ofSeconds(10L))));
                assertThrows(IllegalArgumentException.class,
                        () -> store.issueCredentialConfirmationChallenge(issuance(lifecycle,
                                REALM, AUDIENCE, 2_048, 2, Duration.ofSeconds(10L))));
            }
            assertEquals(Optional.of(initial),
                    store.getCredentialConfirmationChallenge(lifecycle.credentialId()));
        }
    }

    @Test
    void concurrentIssuanceSerializesToOneExactRecord() throws Exception {
        try (FilesystemPkiStore store = open("concurrent")) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "concurrent");
            CredentialConfirmationChallengeIssuance first = issuance(lifecycle, REALM, AUDIENCE, 8_192,
                    1, Duration.ofSeconds(10L));
            CredentialConfirmationChallengeIssuance second = issuance(lifecycle, REALM, AUDIENCE, 8_192,
                    2, Duration.ofSeconds(20L));
            CountDownLatch start = new CountDownLatch(1);
            try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
                Future<CredentialConfirmationChallenge> left = executor.submit(() -> {
                    start.await();
                    return store.issueCredentialConfirmationChallenge(first);
                });
                Future<CredentialConfirmationChallenge> right = executor.submit(() -> {
                    start.await();
                    return store.issueCredentialConfirmationChallenge(second);
                });
                start.countDown();
                CredentialConfirmationChallenge committed = left.get();
                assertEquals(committed, right.get());
                assertTrue(java.util.Arrays.equals(committed.rawChallenge(), first.rawChallenge())
                        || java.util.Arrays.equals(committed.rawChallenge(), second.rawChallenge()));
                assertEquals(Optional.of(committed),
                        store.getCredentialConfirmationChallenge(lifecycle.credentialId()));
            }
        }
    }

    @Test
    void reopensCanonicalPendingChallengeIncludingExpiredRecord() throws Exception {
        java.nio.file.Path root = temporary.resolve("reopen");
        CredentialConfirmationChallenge committed;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "reopen");
            committed = store.issueCredentialConfirmationChallenge(issuance(lifecycle, REALM, AUDIENCE,
                    8_192, 1, Duration.ofSeconds(10L)));
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            assertEquals(Optional.of(committed),
                    reopened.getCredentialConfirmationChallenge(committed.credentialId()));
        }
    }

    @Test
    void rejectsCorruptChallengeAtStartup() throws Exception {
        java.nio.file.Path root = temporary.resolve("corrupt");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "corrupt");
            store.issueCredentialConfirmationChallenge(issuance(lifecycle, REALM, AUDIENCE,
                    8_192, 1, Duration.ofSeconds(10L)));
            replaceMetadata(metadata(store), challengeKey(lifecycle.credentialId()), new byte[] { 1 });
        }
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK));
    }

    @Test
    void rejectsChallengeStoredUnderAnotherCanonicalKeyAtStartup() throws Exception {
        java.nio.file.Path root = temporary.resolve("wrong-key");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "authority");
            Credential other = putCredential(store, "other");
            CredentialConfirmationChallenge challenge = CredentialConfirmationChallenge.create(
                    REALM, AUDIENCE, lifecycle, new ConfirmationProofSuiteBinding(lifecycle.proofSuite(), 8_192),
                    nonce(1), ISSUED_AT, EXPIRES_AT);
            createMetadata(metadata(store), challengeKey(other.credentialId()),
                    CredentialConfirmationChallengeCodec.encode(challenge));
        }
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK));
    }

    @Test
    void rejectsCanonicalChallengeWhoseFrozenLifecycleBindingDiffersAtStartup() throws Exception {
        java.nio.file.Path root = temporary.resolve("mismatched-lifecycle-binding");
        CredentialConfirmationChallenge injected;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            CredentialConfirmationLifecycle authoritative = pending(store, "mismatched-lifecycle-binding");
            CredentialConfirmationLifecycle mismatched = CredentialConfirmationLifecycle.initialize(
                    new CredentialConfirmationInitialization(authoritative.credentialId(),
                            authoritative.initialPolicy(), "9".repeat(64),
                            authoritative.confirmationRequired(), authoritative.confirmationReviewAt(),
                            authoritative.proofSuite()));
            injected = CredentialConfirmationChallenge.create(REALM, AUDIENCE, mismatched,
                    new ConfirmationProofSuiteBinding(mismatched.proofSuite(), 8_192),
                    nonce(1), ISSUED_AT, EXPIRES_AT);
            byte[] encoded = CredentialConfirmationChallengeCodec.encode(injected);
            assertEquals(injected, CredentialConfirmationChallengeCodec.decode(encoded));
            createMetadata(metadata(store), challengeKey(authoritative.credentialId()), encoded);
        }

        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK));
    }

    @Test
    void wrongPendingLifecycleCommitmentLeavesAllThreeRecordsUsable() throws Exception {
        try (FilesystemPkiStore store = open("wrong-pending-commitment")) {
            CredentialConfirmationLifecycle pending = pending(store, "wrong-pending-commitment");
            CredentialConfirmationChallenge challenge = store.issueCredentialConfirmationChallenge(
                    issuance(pending, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L)));
            CredentialConfirmationProofCas wrong = new CredentialConfirmationProofCas(
                    pending.credentialId(), pending.revision(), "9".repeat(64),
                    challenge.recordCommitment());

            assertThrows(IllegalArgumentException.class,
                    () -> store.completeCredentialConfirmation(wrong));
            assertEquals(Optional.of(pending),
                    store.getCredentialConfirmation(pending.credentialId()));
            assertEquals(Optional.of(challenge),
                    store.getCredentialConfirmationChallenge(pending.credentialId()));
            assertEquals(List.of(pending.credentialId()), store.pagePendingCredentialConfirmationReviews(
                    store.getCredential(pending.credentialId()).orElseThrow().issuerRef().caId(),
                    Optional.empty(), pending.confirmationReviewAt(), Optional.empty(), 10)
                    .reviews().stream().map(value -> value.credentialId()).toList());

            assertEquals(CredentialConfirmationLifecycle.State.CONFIRMED,
                    store.completeCredentialConfirmation(
                            proof(pending, challenge.recordCommitment())).state());
        }
    }

    @Test
    void rejectsChallengeWhoseLifecycleIsNoLongerPendingAtStartup() throws Exception {
        java.nio.file.Path root = temporary.resolve("non-pending");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "non-pending");
            CredentialConfirmationChallenge challenge = store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE,
                    8_192, 1, Duration.ofSeconds(10L)));
            CredentialConfirmationLifecycle confirmed = lifecycle.deriveConfirmed(
                    new CredentialConfirmationProofCas(lifecycle.credentialId(), lifecycle.revision(),
                            lifecycle.recordCommitment(), challenge.recordCommitment()), ISSUED_AT);
            replaceMetadata(metadata(store), recordKey(lifecycle.credentialId()),
                    CredentialConfirmationLifecycleCodec.encode(confirmed));
        }
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK));
    }

    @Test
    void acceptsTtlEndingAtMaximumSupportedEpochSecond() throws Exception {
        Instant maximum = Instant.ofEpochSecond(MAXIMUM_CONFIRMATION_EPOCH_SECOND);
        MutableClock clock = new MutableClock(maximum.minusSeconds(10L));
        try (FilesystemPkiStore store = open("maximum-expiry", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "maximum-expiry",
                    new Validity(Instant.EPOCH, maximum));

            CredentialConfirmationChallenge challenge = store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L)));

            assertEquals(maximum.minusSeconds(10L), challenge.issuedAt());
            assertEquals(maximum, challenge.expiresAt());
            assertEquals(Optional.of(challenge),
                    store.getCredentialConfirmationChallenge(lifecycle.credentialId()));
        }
    }

    @Test
    void rejectsExpiryBeyondMaximumWithoutPersistingChallenge() throws Exception {
        Instant maximum = Instant.ofEpochSecond(MAXIMUM_CONFIRMATION_EPOCH_SECOND);
        MutableClock clock = new MutableClock(maximum.minusSeconds(9L));
        try (FilesystemPkiStore store = open("beyond-maximum", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "beyond-maximum",
                    new Validity(Instant.EPOCH, maximum));

            assertThrows(IllegalStateException.class, () -> store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L))));
            assertTrue(store.getCredentialConfirmationChallenge(lifecycle.credentialId()).isEmpty());
        }
    }

    @Test
    void rejectsClockBeforeEpochWithoutPersistingChallenge() throws Exception {
        Instant observation = Instant.ofEpochSecond(-1L);
        MutableClock clock = new MutableClock(observation);
        try (FilesystemPkiStore store = open("before-epoch", clock)) {
            CredentialConfirmationLifecycle lifecycle = pending(store, "before-epoch",
                    new Validity(observation.minusSeconds(1L), Instant.EPOCH.plusSeconds(100L)));

            assertThrows(IllegalStateException.class, () -> store.issueCredentialConfirmationChallenge(
                    issuance(lifecycle, REALM, AUDIENCE, 8_192, 1, Duration.ofSeconds(10L))));
            assertTrue(store.getCredentialConfirmationChallenge(lifecycle.credentialId()).isEmpty());
        }
    }

    private FilesystemPkiStore open(String name) {
        return new FilesystemPkiStore(temporary.resolve(name), FsPkiStoreOptions.defaults(), CLOCK);
    }

    private FilesystemPkiStore open(String name, Clock clock) {
        return new FilesystemPkiStore(temporary.resolve(name), FsPkiStoreOptions.defaults(), clock);
    }

    private static CredentialConfirmationLifecycle pending(FilesystemPkiStore store, String identity)
            throws Exception {
        return pending(store, identity,
                new Validity(Instant.EPOCH, Instant.EPOCH.plusSeconds(7_200L)));
    }

    private static CredentialConfirmationLifecycle pending(FilesystemPkiStore store, String identity,
            Validity validity) throws Exception {
        Credential credential = putCredential(store, identity, validity);
        return store.initializeCredentialConfirmation(new CredentialConfirmationInitialization(
                credential.credentialId(), ConfirmationDisclosurePolicy.AUTHENTICATED,
                "1".repeat(64), true, Instant.EPOCH.plusSeconds(50L), proofSuite()));
    }

    private static Credential putCredential(FilesystemPkiStore store, String identity) throws Exception {
        return putCredential(store, identity,
                new Validity(Instant.EPOCH, Instant.EPOCH.plusSeconds(7_200L)));
    }

    private static Credential putCredential(FilesystemPkiStore store, String identity,
            Validity validity) throws Exception {
        Credential base = FilesystemPkiStoreTest.TestObjects.minimalCredential(store,
                "serial-" + identity, "confirmation-profile");
        Credential exact = new Credential(new PkiId(identity), base.formatId(), base.issuerRef(),
                base.subjectRef(), validity, base.serialOrUniqueId(), base.publicKeyId(),
                base.profileBinding(), base.status(), base.content(), base.attributes());
        store.putCredential(exact);
        return exact;
    }

    private static CredentialConfirmationChallengeIssuance issuance(CredentialConfirmationLifecycle lifecycle,
            ConfirmationRealmBinding realm, String audience, int rsaMaximumModulusBits,
            int nonceSeed, Duration timeToLive) {
        ConfirmationProofSuiteBinding suite = new ConfirmationProofSuiteBinding(
                lifecycle.proofSuite(), rsaMaximumModulusBits);
        return new CredentialConfirmationChallengeIssuance(realm, audience, lifecycle.credentialId(),
                lifecycle.revision(), lifecycle.recordCommitment(), suite, nonce(nonceSeed), timeToLive);
    }

    private static CredentialConfirmationProofCas proof(CredentialConfirmationLifecycle lifecycle,
            String challengeCommitment) {
        return new CredentialConfirmationProofCas(lifecycle.credentialId(), lifecycle.revision(),
                lifecycle.recordCommitment(), challengeCommitment);
    }

    private static byte[] nonce(int seed) {
        byte[] nonce = new byte[CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES];
        java.util.Arrays.fill(nonce, (byte) seed);
        return nonce;
    }

    private static ConfirmationProofSuiteRef proofSuite() {
        return new ConfirmationProofSuiteRef("holder-proof.v1", "2".repeat(64));
    }

    private static SegmentedTransactionalMetadataStore metadata(FilesystemPkiStore store) throws Exception {
        Field field = FilesystemPkiStore.class.getDeclaredField("metadataStore");
        field.setAccessible(true);
        return (SegmentedTransactionalMetadataStore) field.get(store);
    }

    private static MetadataKey challengeKey(PkiId credentialId) throws Exception {
        Method method = FilesystemPkiStore.class.getDeclaredMethod("confirmationChallengeKey", PkiId.class);
        method.setAccessible(true);
        return (MetadataKey) method.invoke(null, credentialId);
    }

    private static MetadataKey recordKey(PkiId credentialId) throws Exception {
        Method method = FilesystemPkiStore.class.getDeclaredMethod("confirmationRecordKey", PkiId.class);
        method.setAccessible(true);
        return (MetadataKey) method.invoke(null, credentialId);
    }

    private static void createMetadata(SegmentedTransactionalMetadataStore metadata,
            MetadataKey key, byte[] content) throws Exception {
        MetadataCommitResult result = metadata.directCommit(List.of(
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE, key, -1L, content)));
        assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
    }

    private static void replaceMetadata(SegmentedTransactionalMetadataStore metadata,
            MetadataKey key, byte[] content) throws Exception {
        long revision;
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
            revision = record.recordRevision();
        }
        MetadataCommitResult result = metadata.directCommit(List.of(
                new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.REPLACE, key, revision, content)));
        assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
    }

    private static final class MutableClock extends Clock {
        private final AtomicReference<Instant> current;
        private final AtomicInteger observations = new AtomicInteger();

        private MutableClock(Instant initial) {
            current = new AtomicReference<>(initial);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (!ZoneOffset.UTC.equals(zone)) {
                throw new IllegalArgumentException("Test clock supports UTC only");
            }
            return this;
        }

        @Override
        public Instant instant() {
            observations.incrementAndGet();
            return current.get();
        }

        private void set(Instant value) {
            current.set(value);
        }

        private int observations() {
            return observations.get();
        }

        private Instant current() {
            return current.get();
        }

        private void resetObservations() {
            observations.set(0);
        }
    }
}
