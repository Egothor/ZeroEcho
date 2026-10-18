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
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.confirmation.ConfirmationDisclosurePolicy;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteBinding;
import zeroecho.pki.api.confirmation.ConfirmationProofSuiteRef;
import zeroecho.pki.api.confirmation.ConfirmationRealmBinding;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallengeIssuance;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationReview;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewPage;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationReason;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;

class FilesystemCredentialConfirmationTest {
    private static final Instant NOW = Instant.EPOCH.plusSeconds(30L);
    private static final Clock CLOCK = Clock.fixed(Instant.EPOCH.plusSeconds(60L), ZoneOffset.UTC);
    private static final String REVIEW_NAMESPACE = "io.zeroecho.pki.confirmation-review";
    private static final String CHALLENGE_NAMESPACE = "io.zeroecho.pki.confirmation-challenge";
    private static final ConfirmationRealmBinding REALM = new ConfirmationRealmBinding("test-realm");
    private static final String AUDIENCE = "https://pki.example.test/confirmation";
    private static final PkiId AUTHORITY = new PkiId("confirmation-authority");
    private static final String PROFILE = "confirmation-profile";

    @TempDir
    private java.nio.file.Path temporary;

    @Test
    void initializesIdempotentlyRejectsConflictAndConfirmsWithTerminalRetry() throws Exception {
        try (FilesystemPkiStore store = open("lifecycle")) {
            Credential credential = putCredential(store, "credential-main");
            CredentialConfirmationInitialization initialization = initialization(
                    credential.credentialId(), NOW.plusSeconds(10L));

            CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(initialization);
            assertEquals(pending, store.initializeCredentialConfirmation(initialization));
            assertThrows(IllegalArgumentException.class, () -> store.initializeCredentialConfirmation(
                    new CredentialConfirmationInitialization(credential.credentialId(),
                            ConfirmationDisclosurePolicy.RESTRICTED, "3".repeat(64), true,
                            initialization.confirmationReviewAt(), initialization.proofSuite())));
            assertEquals(List.of(pending.credentialId()), store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), pending.confirmationReviewAt(), Optional.empty(), 10)
                    .reviews().stream().map(CredentialConfirmationReview::credentialId).toList());

            CredentialConfirmationChallenge challenge = issueChallenge(store, pending, 1);
            CredentialConfirmationProofCas confirmation = proof(pending, challenge.recordCommitment());
            CredentialConfirmationLifecycle confirmed = store.completeCredentialConfirmation(confirmation);
            assertEquals(CredentialConfirmationLifecycle.State.CONFIRMED, confirmed.state());
            assertEquals(Optional.of(CLOCK.instant()), confirmed.confirmedAt());
            assertEquals(confirmed, store.completeCredentialConfirmation(confirmation));
            assertThrows(IllegalArgumentException.class, () -> store.completeCredentialConfirmation(
                    proof(pending, "4".repeat(64))));
            assertTrue(store.getCredentialConfirmationChallenge(credential.credentialId()).isEmpty());
            assertTrue(store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), pending.confirmationReviewAt(), Optional.empty(), 10)
                    .reviews().isEmpty());
        }
    }

    @Test
    void pagesByReviewTimeAndUnsignedUtf8IdentityWithCutoffBoundExclusiveCursor() throws Exception {
        try (FilesystemPkiStore store = open("paging")) {
            Credential early = putCredential(store, "z");
            Credential first = putCredential(store, "a");
            Credential second = putCredential(store, "b");
            store.initializeCredentialConfirmation(initialization(early.credentialId(), NOW));
            store.initializeCredentialConfirmation(initialization(first.credentialId(), NOW.plusSeconds(1L)));
            store.initializeCredentialConfirmation(initialization(second.credentialId(), NOW.plusSeconds(1L)));

            CredentialConfirmationReviewPage page = store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW.plusSeconds(1L), Optional.empty(), 2);
            assertEquals(List.of("z", "a"), page.reviews().stream()
                    .map(value -> value.credentialId().value()).toList());
            CredentialConfirmationReviewCursor cursor = page.nextCursor().orElseThrow();
            assertEquals(List.of("b"), store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW.plusSeconds(1L), Optional.of(cursor), 2).reviews().stream()
                    .map(value -> value.credentialId().value()).toList());
            assertThrows(IllegalArgumentException.class, () -> store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW.plusSeconds(2L), Optional.of(cursor), 2));
            assertThrows(IllegalArgumentException.class, () -> store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW, Optional.empty(), 0));
            assertEquals(List.of("z"), store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW, Optional.empty(), 10).reviews().stream()
                    .map(value -> value.credentialId().value()).toList());
        }
    }

    @Test
    void isolatesAuthorityAndOptionalProfileAndBindsCursorToExactQueryScopeAndStore() throws Exception {
        PkiId otherAuthority = new PkiId("other-confirmation-authority");
        try (FilesystemPkiStore store = open("scope-isolation")) {
            Credential profileAFirst = putCredential(store, "scope-a", AUTHORITY, "profile-a");
            Credential profileB = putCredential(store, "scope-b", AUTHORITY, "profile-b");
            Credential inaccessible = putCredential(store, "scope-c", otherAuthority, "profile-a");
            store.initializeCredentialConfirmation(initialization(
                    profileAFirst.credentialId(), NOW));
            store.initializeCredentialConfirmation(initialization(
                    profileB.credentialId(), NOW.plusSeconds(1L)));
            store.initializeCredentialConfirmation(initialization(
                    inaccessible.credentialId(), NOW));

            CredentialConfirmationReviewPage first = store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW.plusSeconds(1L), Optional.empty(), 1);
            assertEquals(List.of(profileAFirst.credentialId()), first.reviews().stream()
                    .map(CredentialConfirmationReview::credentialId).toList());
            CredentialConfirmationReviewCursor cursor = first.nextCursor().orElseThrow();
            assertEquals(List.of(profileB.credentialId()), store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW.plusSeconds(1L), Optional.of(cursor), 10)
                    .reviews().stream().map(CredentialConfirmationReview::credentialId).toList());
            assertEquals(List.of(profileAFirst.credentialId()),
                    store.pagePendingCredentialConfirmationReviews(AUTHORITY, Optional.of("profile-a"),
                            NOW.plusSeconds(1L), Optional.empty(), 10).reviews().stream()
                            .map(CredentialConfirmationReview::credentialId).toList());
            assertEquals(List.of(inaccessible.credentialId()),
                    store.pagePendingCredentialConfirmationReviews(otherAuthority, Optional.empty(),
                            NOW.plusSeconds(1L), Optional.empty(), 10).reviews().stream()
                            .map(CredentialConfirmationReview::credentialId).toList());
            assertThrows(IllegalArgumentException.class,
                    () -> store.pagePendingCredentialConfirmationReviews(otherAuthority, Optional.empty(),
                            NOW.plusSeconds(1L), Optional.of(cursor), 10));
            assertThrows(IllegalArgumentException.class,
                    () -> store.pagePendingCredentialConfirmationReviews(AUTHORITY, Optional.of("profile-a"),
                            NOW.plusSeconds(1L), Optional.of(cursor), 10));

            try (FilesystemPkiStore otherStore = open("scope-isolation-other-store")) {
                assertThrows(IllegalArgumentException.class,
                        () -> otherStore.pagePendingCredentialConfirmationReviews(AUTHORITY, Optional.empty(),
                                NOW.plusSeconds(1L), Optional.of(cursor), 10));
            }
        }
    }

    @Test
    void rejectsExpiredAndAnyRevocationHistoryAtInitializationAndConfirmation() throws Exception {
        try (FilesystemPkiStore store = open("eligibility")) {
            Credential atExpiryBoundary = putCredential(store, "boundary");
            CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(
                    initialization(atExpiryBoundary.credentialId(), NOW.plusSeconds(1L)));
            CredentialConfirmationChallenge challenge = issueChallenge(store, pending, 1);
            store.transitionRevocation(new RevocationCommand.Hold(atExpiryBoundary.credentialId(),
                    FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);
            assertThrows(IllegalStateException.class, () -> store.completeCredentialConfirmation(
                    proof(pending, challenge.recordCommitment())));

            Credential revoked = putCredential(store, "revoked");
            store.transitionRevocation(new RevocationCommand.Hold(revoked.credentialId(),
                    FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);
            store.transitionRevocation(new RevocationCommand.Unhold(revoked.credentialId(),
                    FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW.plusSeconds(1L));
            assertThrows(IllegalStateException.class, () -> store.initializeCredentialConfirmation(
                    initialization(revoked.credentialId(), NOW.plusSeconds(1L))));
        }

        Clock expiredClock = Clock.fixed(Instant.EPOCH.plusSeconds(61L), ZoneOffset.UTC);
        try (FilesystemPkiStore store = new FilesystemPkiStore(temporary.resolve("expired"),
                FsPkiStoreOptions.defaults(), expiredClock)) {
            Credential expired = putCredential(store, "expired");
            assertThrows(IllegalStateException.class, () -> store.initializeCredentialConfirmation(
                    initialization(expired.credentialId(), Instant.EPOCH.plusSeconds(70L))));
        }
    }

    @Test
    void serializesInitializationAgainstRevocationWithoutPostHistoryAdmission() throws Exception {
        try (FilesystemPkiStore store = open("race")) {
            Credential credential = putCredential(store, "race");
            CountDownLatch start = new CountDownLatch(1);
            try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
                Future<Boolean> initialized = executor.submit(() -> {
                    start.await();
                    try {
                        store.initializeCredentialConfirmation(
                                initialization(credential.credentialId(), NOW.plusSeconds(1L)));
                        return true;
                    } catch (IllegalStateException rejected) {
                        return false;
                    }
                });
                Future<?> revoked = executor.submit(() -> {
                    start.await();
                    store.transitionRevocation(new RevocationCommand.Hold(credential.credentialId(),
                            FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);
                    return null;
                });
                start.countDown();
                boolean admissionWon = initialized.get();
                revoked.get();
                assertEquals(admissionWon, store.getCredentialConfirmation(credential.credentialId()).isPresent());
                assertTrue(store.getRevocation(credential.credentialId()).isPresent());
            }
        }
    }

    @Test
    void serializesCompletionAgainstRevocationWithoutPostHistoryCompletion() throws Exception {
        try (FilesystemPkiStore store = open("completion-race")) {
            Credential credential = putCredential(store, "completion-race");
            CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(
                    initialization(credential.credentialId(), NOW.plusSeconds(1L)));
            CredentialConfirmationChallenge challenge = issueChallenge(store, pending, 1);
            CredentialConfirmationProofCas proof = proof(pending, challenge.recordCommitment());
            CountDownLatch start = new CountDownLatch(1);
            try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
                Future<Boolean> completed = executor.submit(() -> {
                    start.await();
                    try {
                        store.completeCredentialConfirmation(proof);
                        return true;
                    } catch (IllegalStateException rejected) {
                        return false;
                    }
                });
                Future<?> revoked = executor.submit(() -> {
                    start.await();
                    store.transitionRevocation(new RevocationCommand.Hold(credential.credentialId(),
                            FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);
                    return null;
                });
                start.countDown();
                boolean completionWon = completed.get();
                revoked.get();
                CredentialConfirmationLifecycle lifecycle = store.getCredentialConfirmation(
                        credential.credentialId()).orElseThrow();
                assertEquals(completionWon,
                        lifecycle.state() == CredentialConfirmationLifecycle.State.CONFIRMED);
                assertTrue(store.getRevocation(credential.credentialId()).isPresent());
            }
        }
    }

    @Test
    void revokesOnlyPendingNonPublicConfirmationStrictlyAfterReviewBoundary() throws Exception {
        try (FilesystemPkiStore store = open("overdue-boundaries")) {
            Credential before = putCredential(store, "overdue-before");
            store.initializeCredentialConfirmation(initialization(
                    before.credentialId(), CLOCK.instant().plusSeconds(1L)));
            assertThrows(PkiException.class, () -> revokePending(store, before.credentialId()));

            Credential equal = putCredential(store, "overdue-equal");
            store.initializeCredentialConfirmation(initialization(equal.credentialId(), CLOCK.instant()));
            assertThrows(PkiException.class, () -> revokePending(store, equal.credentialId()));

            Credential overdue = putCredential(store, "overdue-after");
            CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(
                    initialization(overdue.credentialId(), CLOCK.instant().minusSeconds(1L)));
            issueChallenge(store, pending, 3);
            zeroecho.pki.api.revocation.RevocationRecord revoked = revokePending(
                    store, overdue.credentialId());
            assertEquals(RevocationState.PERMANENTLY_REVOKED, revoked.transition().state());
            assertEquals(Optional.of(RevocationReason.UNSPECIFIED),
                    revoked.transition().permanentReason());
            assertEquals(CredentialConfirmationLifecycle.State.PENDING,
                    store.getCredentialConfirmation(overdue.credentialId()).orElseThrow().state());
            assertTrue(store.getCredentialConfirmationChallenge(overdue.credentialId()).isEmpty());
            assertTrue(store.pagePendingCredentialConfirmationReviews(AUTHORITY, Optional.empty(),
                    CLOCK.instant(), Optional.empty(), 10).reviews().stream()
                    .noneMatch(review -> review.credentialId().equals(overdue.credentialId())));

            Credential publicCredential = putCredential(store, "overdue-public");
            store.initializeCredentialConfirmation(new CredentialConfirmationInitialization(
                    publicCredential.credentialId(), ConfirmationDisclosurePolicy.PUBLIC,
                    "1".repeat(64), false, CLOCK.instant().minusSeconds(1L),
                    new ConfirmationProofSuiteRef("holder-proof.v1", "2".repeat(64))));
            assertThrows(PkiException.class,
                    () -> revokePending(store, publicCredential.credentialId()));

            Credential confirmedCredential = putCredential(store, "overdue-confirmed");
            CredentialConfirmationLifecycle confirmable = store.initializeCredentialConfirmation(
                    initialization(confirmedCredential.credentialId(), CLOCK.instant().minusSeconds(1L)));
            CredentialConfirmationChallenge challenge = issueChallenge(store, confirmable, 4);
            store.completeCredentialConfirmation(proof(confirmable, challenge.recordCommitment()));
            assertThrows(PkiException.class,
                    () -> revokePending(store, confirmedCredential.credentialId()));

            Credential differentlyRevoked = putCredential(store, "overdue-already-revoked");
            store.initializeCredentialConfirmation(initialization(
                    differentlyRevoked.credentialId(), CLOCK.instant().minusSeconds(1L)));
            store.transitionRevocation(new RevocationCommand.RevokePermanently(
                    differentlyRevoked.credentialId(), RevocationReason.KEY_COMPROMISE,
                    FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);
            assertThrows(PkiException.class,
                    () -> revokePending(store, differentlyRevoked.credentialId()));
        }
    }

    @Test
    void serializesConfirmationAgainstOverdueRevocationWithExactlyOneWinner() throws Exception {
        try (FilesystemPkiStore store = open("overdue-race")) {
            Credential credential = putCredential(store, "overdue-race");
            CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(
                    initialization(credential.credentialId(), CLOCK.instant().minusSeconds(1L)));
            CredentialConfirmationChallenge challenge = issueChallenge(store, pending, 5);
            CredentialConfirmationProofCas proof = proof(pending, challenge.recordCommitment());
            CountDownLatch start = new CountDownLatch(1);
            try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
                Future<Boolean> confirmed = executor.submit(() -> {
                    start.await();
                    try {
                        store.completeCredentialConfirmation(proof);
                        return true;
                    } catch (IllegalStateException rejected) {
                        return false;
                    }
                });
                Future<Boolean> revoked = executor.submit(() -> {
                    start.await();
                    try {
                        revokePending(store, credential.credentialId());
                        return true;
                    } catch (PkiException rejected) {
                        return false;
                    }
                });
                start.countDown();
                assertEquals(1, (confirmed.get() ? 1 : 0) + (revoked.get() ? 1 : 0));
            }
        }
    }

    @Test
    void restartRepairsCleanupInterruptedAfterAuthoritativeRevocation() throws Exception {
        java.nio.file.Path root = temporary.resolve("overdue-cleanup-recovery");
        AtomicBoolean failOnce = new AtomicBoolean(true);
        PkiId credentialId;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK,
                ignored -> {
                    if (failOnce.getAndSet(false)) {
                        throw new java.io.IOException("injected cleanup interruption");
                    }
                })) {
            Credential credential = putCredential(store, "overdue-cleanup-recovery");
            credentialId = credential.credentialId();
            CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(
                    initialization(credentialId, CLOCK.instant().minusSeconds(1L)));
            issueChallenge(store, pending, 6);
            PkiException failure = assertThrows(PkiException.class,
                    () -> revokePending(store, credentialId));
            assertTrue(failure.getMessage().contains("CONFIRMATION_REVOCATION_RECOVERY_REQUIRED"));
            assertEquals(RevocationState.PERMANENTLY_REVOKED,
                    store.getRevocation(credentialId).orElseThrow().transition().state());
            assertTrue(store.getCredentialConfirmationChallenge(credentialId).isEmpty());
            assertTrue(store.pagePendingCredentialConfirmationReviews(AUTHORITY, Optional.empty(),
                    CLOCK.instant(), Optional.empty(), 10).reviews().isEmpty());
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), CLOCK)) {
            assertEquals(RevocationState.PERMANENTLY_REVOKED,
                    revokePending(reopened, credentialId).transition().state());
            assertTrue(reopened.getCredentialConfirmationChallenge(credentialId).isEmpty());
            assertTrue(reopened.pagePendingCredentialConfirmationReviews(AUTHORITY, Optional.empty(),
                    CLOCK.instant(), Optional.empty(), 10).reviews().isEmpty());
        }
    }

    @Test
    void boundedListRepairContinuesAcrossDeletedAnchorsAndConvergesAfterReopen()
            throws Exception {
        java.nio.file.Path root = temporary.resolve("bounded-list-repair");
        PkiId liveId;
        try (FilesystemPkiStore store = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), CLOCK)) {
            for (int index = 0; index < 12; index++) {
                Credential stale = putCredential(store, "stale-" + String.format("%02d", index));
                CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(
                        initialization(stale.credentialId(), NOW.plusSeconds(index)));
                issueChallenge(store, pending, index + 1);
                store.transitionRevocation(new RevocationCommand.RevokePermanently(
                        stale.credentialId(), RevocationReason.UNSPECIFIED,
                        FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);
            }
            Credential live = putCredential(store, "still-actionable");
            liveId = live.credentialId();
            store.initializeCredentialConfirmation(initialization(liveId, NOW.plusSeconds(20L)));

            CredentialConfirmationReviewPage first = store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW.plusSeconds(30L), Optional.empty(), 100);
            assertTrue(first.reviews().isEmpty());
            CredentialConfirmationReviewCursor continuation = first.nextCursor().orElseThrow();
            assertEquals(6, metadataCount(metadata(store), REVIEW_NAMESPACE));
            assertEquals(2, metadataCount(metadata(store), CHALLENGE_NAMESPACE));

            CredentialConfirmationReviewPage second = store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW.plusSeconds(30L),
                    Optional.of(continuation), 100);
            assertEquals(List.of(liveId), second.reviews().stream()
                    .map(CredentialConfirmationReview::credentialId).toList());
            assertTrue(second.nextCursor().isEmpty());
            assertEquals(2, metadataCount(metadata(store), REVIEW_NAMESPACE));
            assertEquals(0, metadataCount(metadata(store), CHALLENGE_NAMESPACE));
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(
                root, FsPkiStoreOptions.defaults(), CLOCK)) {
            CredentialConfirmationReviewPage page = reopened.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), NOW.plusSeconds(30L), Optional.empty(), 100);
            assertEquals(List.of(liveId), page.reviews().stream()
                    .map(CredentialConfirmationReview::credentialId).toList());
            assertTrue(page.nextCursor().isEmpty());
        }
    }

    @Test
    void listRepairRespectsCutoffAndLeavesNonPermanentHistoryUntouched() throws Exception {
        try (FilesystemPkiStore store = open("list-repair-cutoff")) {
            Credential future = putCredential(store, "future-stale");
            CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(
                    initialization(future.credentialId(), NOW.plusSeconds(10L)));
            issueChallenge(store, pending, 1);
            store.transitionRevocation(new RevocationCommand.RevokePermanently(
                    future.credentialId(), RevocationReason.UNSPECIFIED,
                    FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);

            Credential held = putCredential(store, "held-stale");
            store.initializeCredentialConfirmation(initialization(
                    held.credentialId(), NOW.plusSeconds(11L)));
            store.transitionRevocation(new RevocationCommand.Hold(held.credentialId(),
                    FilesystemPkiStoreTest.TestObjects.emptyAttributes()), NOW);

            CredentialConfirmationReviewPage beforeCutoff =
                    store.pagePendingCredentialConfirmationReviews(
                            AUTHORITY, Optional.empty(), NOW, Optional.empty(), 10);
            assertTrue(beforeCutoff.reviews().isEmpty());
            assertTrue(beforeCutoff.nextCursor().isEmpty());
            assertEquals(4, metadataCount(metadata(store), REVIEW_NAMESPACE));
            assertEquals(1, metadataCount(metadata(store), CHALLENGE_NAMESPACE));

            CredentialConfirmationReviewPage repaired =
                    store.pagePendingCredentialConfirmationReviews(
                            AUTHORITY, Optional.empty(), NOW.plusSeconds(20L), Optional.empty(), 10);
            assertTrue(repaired.reviews().isEmpty());
            assertTrue(repaired.nextCursor().isEmpty());
            assertEquals(2, metadataCount(metadata(store), REVIEW_NAMESPACE));
            assertEquals(0, metadataCount(metadata(store), CHALLENGE_NAMESPACE));
        }
    }

    @Test
    void directRepairCohortContinuesAfterExactRevisionConflictAndUnknownFailsSafe()
            throws Exception {
        try (FilesystemPkiStore store = open("list-repair-outcomes")) {
            SegmentedTransactionalMetadataStore metadata = metadata(store);
            MetadataKey conflicted = new MetadataKey("io.zeroecho.pki.test-repair", "conflicted");
            MetadataKey progress = new MetadataKey("io.zeroecho.pki.test-repair", "progress");
            createMetadata(metadata, List.of(new MetadataFixture(conflicted, new byte[] { 1 }),
                    new MetadataFixture(progress, new byte[] { 2 })));
            long conflictedRevision = metadataRevision(metadata, conflicted);
            long progressRevision = metadataRevision(metadata, progress);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, metadata.directCommit(List.of(
                    new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.DELETE,
                            conflicted, conflictedRevision, null))).outcome());
            List<MetadataCommitResult> results = metadata.directCommitCohort(List.of(
                    List.of(new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.DELETE,
                            conflicted, conflictedRevision, null)),
                    List.of(new SigningTransactionPayloadCodec.Mutation(
                            SigningTransactionPayloadCodec.MutationKind.DELETE,
                            progress, progressRevision, null))));
            assertEquals(List.of(MetadataCommitResult.Outcome.NOT_COMMITTED,
                    MetadataCommitResult.Outcome.COMMITTED),
                    results.stream().map(MetadataCommitResult::outcome).toList());
            assertTrue(metadataMissing(metadata, progress));

            Method handler = FilesystemPkiStore.class.getDeclaredMethod(
                    "requireKnownOpportunisticConfirmationRepair", MetadataCommitResult.class);
            handler.setAccessible(true);
            zeroecho.pki.spi.store.MetadataStoreId storeId;
            try (MetadataSnapshot snapshot = metadata.snapshot()) {
                storeId = snapshot.storeId();
            }
            MetadataCommitResult unknown = new MetadataCommitResult(
                    new zeroecho.pki.spi.store.MetadataTransactionId(
                            storeId, "0".repeat(32)), MetadataCommitResult.Outcome.UNKNOWN,
                    OptionalLong.empty(), Optional.empty());
            java.lang.reflect.InvocationTargetException failure = assertThrows(
                    java.lang.reflect.InvocationTargetException.class,
                    () -> handler.invoke(store, unknown));
            assertTrue(failure.getCause() instanceof PkiException);
            assertTrue(failure.getCause().getMessage().contains("STORE_DURABILITY_UNCONFIRMED"));
        }
    }

    @Test
    void reopensAndRebuildsCorruptDerivedReviewWithoutChangingAuthority() throws Exception {
        java.nio.file.Path root = temporary.resolve("rebuild");
        CredentialConfirmationLifecycle pending;
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            Credential credential = putCredential(store, "rebuild");
            pending = store.initializeCredentialConfirmation(
                    initialization(credential.credentialId(), NOW.plusSeconds(1L)));
            corruptOnlyReviewProjection(store);
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            assertEquals(Optional.of(pending), reopened.getCredentialConfirmation(pending.credentialId()));
            assertEquals(List.of(pending.credentialId()), reopened.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), pending.confirmationReviewAt(), Optional.empty(), 10)
                    .reviews().stream().map(CredentialConfirmationReview::credentialId).toList());
        }
    }

    @Test
    void rejectsInvalidEarlyReviewKeyBeforeFuturePayloadCanEndPage() throws Exception {
        try (FilesystemPkiStore store = open("early-invalid-review")) {
            Credential credential = putCredential(store, "future-review");
            CredentialConfirmationLifecycle future = store.initializeCredentialConfirmation(
                    initialization(credential.credentialId(), NOW.plusSeconds(20L)));
            createMetadata(metadata(store), List.of(new MetadataFixture(
                    reviewKey(new CredentialConfirmationReview(future.credentialId(), AUTHORITY,
                            PROFILE, NOW, ConfirmationDisclosurePolicy.AUTHENTICATED), false),
                    CredentialConfirmationReviewCodec.encode(review(future)))));

            assertThrows(IllegalStateException.class,
                    () -> store.pagePendingCredentialConfirmationReviews(
                            AUTHORITY, Optional.empty(), NOW.plusSeconds(1L), Optional.empty(), 10));
        }
    }

    @Test
    void rejectsTerminalLifecycleStoredUnderAnotherCredentialAuthorityKey() throws Exception {
        try (FilesystemPkiStore store = open("terminal-identity")) {
            PkiId requested = new PkiId("requested-terminal");
            CredentialConfirmationLifecycle pending = CredentialConfirmationLifecycle.initialize(
                    initialization(new PkiId("stored-terminal"), NOW.plusSeconds(1L)));
            Instant confirmedAt = NOW.plusSeconds(2L);
            CredentialConfirmationLifecycle confirmed = pending.deriveConfirmed(
                    proof(pending, "5".repeat(64)), confirmedAt);
            createMetadata(metadata(store), List.of(new MetadataFixture(recordKey(requested),
                    CredentialConfirmationLifecycleCodec.encode(confirmed))));

            CredentialConfirmationProofCas retry = proof(requested, pending,
                    confirmed.consumedChallengeRecordCommitment().orElseThrow());
            assertThrows(IllegalStateException.class, () -> store.completeCredentialConfirmation(retry));
            assertThrows(IllegalStateException.class, () -> store.getCredentialConfirmation(requested));
        }
    }

    @Test
    void rebuildsMultipleBoundedMixedBatchesAndIsIdempotentAcrossReopens() throws Exception {
        java.nio.file.Path root = temporary.resolve("multi-batch-rebuild");
        List<CredentialConfirmationLifecycle> pending = new ArrayList<>();
        List<MetadataFixture> authority = new ArrayList<>();
        List<MetadataFixture> partialProjection = new ArrayList<>();
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            for (int index = 0; index < 100; index++) {
                PkiId credentialId = new PkiId("batch-" + String.format("%03d", index));
                putCredential(store, credentialId.value());
                CredentialConfirmationLifecycle lifecycle = CredentialConfirmationLifecycle.initialize(
                        initialization(credentialId,
                                NOW.plusSeconds(index + 1L)));
                pending.add(lifecycle);
                authority.add(new MetadataFixture(recordKey(lifecycle.credentialId()),
                        CredentialConfirmationLifecycleCodec.encode(lifecycle)));
                if (index < 31) {
                    partialProjection.add(new MetadataFixture(reviewKey(review(lifecycle), false),
                            CredentialConfirmationReviewCodec.encode(review(lifecycle))));
                } else if (index < 36) {
                    partialProjection.add(new MetadataFixture(reviewKey(review(lifecycle), false), new byte[] { 1 }));
                } else if (index < 41) {
                    CredentialConfirmationReview stale = new CredentialConfirmationReview(
                            lifecycle.credentialId(), AUTHORITY, PROFILE, lifecycle.confirmationReviewAt(),
                            ConfirmationDisclosurePolicy.RESTRICTED);
                    partialProjection.add(new MetadataFixture(reviewKey(review(lifecycle), false),
                            CredentialConfirmationReviewCodec.encode(stale)));
                }
            }
            putCredential(store, "confirmed-with-stale-review");
            CredentialConfirmationLifecycle confirmedAuthority = CredentialConfirmationLifecycle.initialize(
                    initialization(new PkiId("confirmed-with-stale-review"), NOW.plusSeconds(500L)));
            CredentialConfirmationLifecycle confirmed = confirmedAuthority.deriveConfirmed(
                    proof(confirmedAuthority, "7".repeat(64)), NOW);
            authority.add(new MetadataFixture(recordKey(confirmed.credentialId()),
                    CredentialConfirmationLifecycleCodec.encode(confirmed)));
            partialProjection.add(new MetadataFixture(reviewKey(review(confirmedAuthority), false),
                    CredentialConfirmationReviewCodec.encode(review(confirmedAuthority))));
            for (int index = 0; index < 65; index++) {
                CredentialConfirmationLifecycle orphan = CredentialConfirmationLifecycle.initialize(
                        initialization(new PkiId("orphan-" + String.format("%03d", index)),
                                NOW.plusSeconds(1_000L + index)));
                partialProjection.add(new MetadataFixture(reviewKey(review(orphan), false),
                        CredentialConfirmationReviewCodec.encode(review(orphan))));
            }
            SegmentedTransactionalMetadataStore metadata = metadata(store);
            createMetadata(metadata, authority);
            createMetadata(metadata, partialProjection);
        }

        assertCanonicalRebuild(root, pending);
        assertCanonicalRebuild(root, pending);
    }

    @Test
    void acceptsInitializationAndConfirmationAtExactCredentialNotAfter() throws Exception {
        try (FilesystemPkiStore store = open("not-after-boundary")) {
            Credential credential = putCredential(store, "not-after-boundary");
            assertEquals(Instant.EPOCH.plusSeconds(60L), credential.validity().notAfter());
            CredentialConfirmationLifecycle pending = store.initializeCredentialConfirmation(
                    initialization(credential.credentialId(), NOW.plusSeconds(1L)));
            CredentialConfirmationChallenge challenge = issueChallenge(store, pending, 1);
            CredentialConfirmationLifecycle confirmed = store.completeCredentialConfirmation(
                    proof(pending, challenge.recordCommitment()));
            assertEquals(CredentialConfirmationLifecycle.State.CONFIRMED, confirmed.state());
        }
    }

    private FilesystemPkiStore open(String name) {
        return new FilesystemPkiStore(temporary.resolve(name), FsPkiStoreOptions.defaults(), CLOCK);
    }

    private static Credential putCredential(FilesystemPkiStore store, String credentialId) throws Exception {
        return putCredential(store, credentialId, AUTHORITY, PROFILE);
    }

    private static Credential putCredential(FilesystemPkiStore store, String credentialId,
            PkiId authorityId, String profileId) throws Exception {
        Credential base = FilesystemPkiStoreTest.TestObjects.minimalCredential(store,
                "serial-" + credentialId, profileId);
        Credential exact = new Credential(new PkiId(credentialId), base.formatId(), new IssuerRef(authorityId),
                base.subjectRef(), base.validity(), base.serialOrUniqueId(), base.publicKeyId(),
                base.profileBinding(), base.status(), base.content(), base.attributes());
        store.putCredential(exact);
        return exact;
    }

    private static CredentialConfirmationInitialization initialization(PkiId credentialId, Instant reviewAt) {
        return new CredentialConfirmationInitialization(credentialId,
                ConfirmationDisclosurePolicy.AUTHENTICATED, "1".repeat(64), true, reviewAt,
                new ConfirmationProofSuiteRef("holder-proof.v1", "2".repeat(64)));
    }

    private static CredentialConfirmationChallenge issueChallenge(FilesystemPkiStore store,
            CredentialConfirmationLifecycle lifecycle, int nonceSeed) {
        return store.issueCredentialConfirmationChallenge(new CredentialConfirmationChallengeIssuance(
                REALM, AUDIENCE, lifecycle.credentialId(), lifecycle.revision(), lifecycle.recordCommitment(),
                new ConfirmationProofSuiteBinding(lifecycle.proofSuite(), 8_192),
                nonce(nonceSeed), Duration.ofSeconds(10L)));
    }

    private static CredentialConfirmationProofCas proof(CredentialConfirmationLifecycle lifecycle,
            String challengeCommitment) {
        return proof(lifecycle.credentialId(), lifecycle, challengeCommitment);
    }

    private static zeroecho.pki.api.revocation.RevocationRecord revokePending(
            FilesystemPkiStore store, PkiId credentialId) {
        return store.revokeOverduePendingCredentialConfirmation(
                new RevocationCommand.RevokePermanently(credentialId, RevocationReason.UNSPECIFIED,
                        FilesystemPkiStoreTest.TestObjects.emptyAttributes()));
    }

    private static CredentialConfirmationProofCas proof(PkiId credentialId,
            CredentialConfirmationLifecycle lifecycle, String challengeCommitment) {
        return new CredentialConfirmationProofCas(credentialId, lifecycle.revision(),
                lifecycle.recordCommitment(), challengeCommitment);
    }

    private static byte[] nonce(int seed) {
        byte[] nonce = new byte[CredentialConfirmationChallenge.RAW_CHALLENGE_BYTES];
        java.util.Arrays.fill(nonce, (byte) seed);
        return nonce;
    }

    private static void corruptOnlyReviewProjection(FilesystemPkiStore store) throws Exception {
        SegmentedTransactionalMetadataStore metadata = metadata(store);
        zeroecho.pki.spi.store.MetadataKey key;
        long revision;
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(REVIEW_NAMESPACE),
                        CancellationSignal.NONE)) {
            try (MetadataSnapshot.Record record = cursor.next(CancellationSignal.NONE).orElseThrow()) {
                key = record.key();
                revision = record.recordRevision();
            }
        }
        try (MetadataTransaction transaction = metadata.beginTransaction()) {
            transaction.replace(key, revision, bytes(new byte[] { 1 }), CancellationSignal.NONE);
            MetadataCommitResult result = transaction.commit();
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
            metadata.acknowledge(result.transactionId());
        }
    }

    private void assertCanonicalRebuild(java.nio.file.Path root,
            List<CredentialConfirmationLifecycle> expected) throws Exception {
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults(), CLOCK)) {
            CredentialConfirmationReviewPage page = store.pagePendingCredentialConfirmationReviews(
                    AUTHORITY, Optional.empty(), Instant.EPOCH.plusSeconds(2_000L), Optional.empty(), 4096);
            assertEquals(expected.stream().map(CredentialConfirmationLifecycle::credentialId).toList(),
                    page.reviews().stream().map(CredentialConfirmationReview::credentialId).toList());
            assertTrue(page.nextCursor().isEmpty());
            assertEquals(expected.size() * 2, metadataCount(metadata(store), REVIEW_NAMESPACE));
        }
    }

    private static SegmentedTransactionalMetadataStore metadata(FilesystemPkiStore store) throws Exception {
        Field field = FilesystemPkiStore.class.getDeclaredField("metadataStore");
        field.setAccessible(true);
        return (SegmentedTransactionalMetadataStore) field.get(store);
    }

    private static MetadataKey recordKey(PkiId credentialId) throws Exception {
        Method method = FilesystemPkiStore.class.getDeclaredMethod("confirmationRecordKey", PkiId.class);
        method.setAccessible(true);
        return (MetadataKey) method.invoke(null, credentialId);
    }

    private static MetadataKey reviewKey(CredentialConfirmationReview review,
            boolean profileScoped) throws Exception {
        Method method = FilesystemPkiStore.class.getDeclaredMethod(
                "confirmationReviewKey", CredentialConfirmationReview.class, boolean.class);
        method.setAccessible(true);
        return (MetadataKey) method.invoke(null, review, profileScoped);
    }

    private static CredentialConfirmationReview review(CredentialConfirmationLifecycle lifecycle) {
        return new CredentialConfirmationReview(lifecycle.credentialId(), AUTHORITY, PROFILE,
                lifecycle.confirmationReviewAt(), lifecycle.initialPolicy());
    }

    private static void createMetadata(SegmentedTransactionalMetadataStore metadata,
            List<MetadataFixture> fixtures) throws Exception {
        int offset = 0;
        while (offset < fixtures.size()) {
            int end = Math.min(offset + 31, fixtures.size());
            List<SigningTransactionPayloadCodec.Mutation> mutations = new ArrayList<>(end - offset);
            for (int index = offset; index < end; index++) {
                MetadataFixture fixture = fixtures.get(index);
                mutations.add(new SigningTransactionPayloadCodec.Mutation(
                        SigningTransactionPayloadCodec.MutationKind.CREATE,
                        fixture.key(), -1L, fixture.value()));
            }
            MetadataCommitResult result = metadata.directCommit(mutations);
            assertEquals(MetadataCommitResult.Outcome.COMMITTED, result.outcome());
            offset = end;
        }
    }

    private static int metadataCount(SegmentedTransactionalMetadataStore metadata,
            String namespace) throws Exception {
        int count = 0;
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(namespace),
                        CancellationSignal.NONE)) {
            while (cursor.next(CancellationSignal.NONE).isPresent()) {
                count++;
            }
        }
        return count;
    }

    private static long metadataRevision(SegmentedTransactionalMetadataStore metadata,
            MetadataKey key) throws Exception {
        try (MetadataSnapshot snapshot = metadata.snapshot();
                MetadataSnapshot.Record record = snapshot.get(key).orElseThrow()) {
            return record.recordRevision();
        }
    }

    private static boolean metadataMissing(SegmentedTransactionalMetadataStore metadata,
            MetadataKey key) throws Exception {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            return snapshot.get(key).isEmpty();
        }
    }

    private record MetadataFixture(MetadataKey key, byte[] value) { }

    private static RepeatableContent bytes(byte[] value) {
        return new RepeatableContent() {
            @Override public OptionalLong length() { return OptionalLong.of(value.length); }
            @Override public java.io.InputStream openStream() {
                return new java.io.ByteArrayInputStream(value.clone());
            }
            @Override public String contentId() { return "confirmation-corruption-fixture"; }
            @Override public void close() { }
        };
    }
}
