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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.FormatId;
import zeroecho.pki.api.IssuerRef;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.SubjectRef;
import zeroecho.pki.api.Validity;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.CaProfileBinding;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialStatus;
import zeroecho.pki.api.publication.PublicationCursor;
import zeroecho.pki.api.publication.PublicationFailure;
import zeroecho.pki.api.publication.PublicationQuery;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationRequest;
import zeroecho.pki.api.publication.PublicationResult;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.publication.PublicationTargetType;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectType;
import zeroecho.pki.impl.core.DefaultPublicationService;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.publish.PublicationAttempt;
import zeroecho.pki.spi.publish.PublicationOutcome;
import zeroecho.pki.spi.publish.Publisher;

final class DefaultPublicationServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-03T10:15:30Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.UTC);
    private static final PublicationTarget TARGET =
            new PublicationTarget(PublicationTargetType.FILESYSTEM, "primary-mirror-v1");

    @TempDir
    private Path temporaryDirectory;

    @AfterEach
    void clearFaults() {
        FilesystemPkiStore.clearPublicationCommitFault();
    }

    @Test
    void registrationRequiresCommittedExactSourceAndIsIdempotent() throws Exception {
        System.out.println("registrationRequiresCommittedExactSourceAndIsIdempotent");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore store = store("registration");
                DefaultPublicationService service = service(store, publisher)) {
            Credential credential = credential(store, "registration-one", new byte[] { 1, 2, 3 });
            PublicationRequest request = credentialRequest("publication-registration", credential);
            assertThrows(IllegalArgumentException.class, () -> service.register(request));
            assertEquals(0, publisher.dispatchCalls.get());

            store.putCredential(credential);
            Set<zeroecho.pki.api.content.DurableContentOwner> ownersBefore =
                    store.stagedContent().contentOwners(credential.content());
            PublicationRecord first = service.register(request);
            PublicationRecord replay = service.register(request);
            assertEquals(PublicationStatus.PENDING, first.status());
            assertEquals(first, replay);
            assertEquals(ownersBefore, store.stagedContent().contentOwners(credential.content()));
            assertEquals(0, publisher.dispatchCalls.get());

            Credential other = credential(store, "registration-two", new byte[] { 4, 5, 6 });
            store.putCredential(other);
            PublicationRequest conflict = new PublicationRequest(first.publicationId(),
                    PublicationSourceType.CREDENTIAL, other.credentialId(), TARGET);
            assertThrows(IllegalArgumentException.class, () -> service.register(conflict));
            PublicationRecord changedTarget = new PublicationRecord(first.publicationId(), first.sourceType(),
                    first.sourceId(), first.content(),
                    new PublicationTarget(PublicationTargetType.FILESYSTEM, "other-mirror-v1"), first.status(),
                    first.attemptNumber(), first.attemptToken(), first.createdAt(), first.updatedAt(),
                    first.failure(), first.evidence());
            assertThrows(IllegalArgumentException.class,
                    () -> store.replacePublicationRecord(first, changedTarget));

            StatusObject status = status(store, "registration-status", new byte[] { 7, 8 });
            store.putStatusObject(status);
            PublicationRecord statusRecord = service.register(statusRequest("publication-status", status));
            assertEquals(status.content(), statusRecord.content());
            assertEquals(PublicationSourceType.STATUS_OBJECT, statusRecord.sourceType());

            PublicationTarget absent = new PublicationTarget(PublicationTargetType.HTTP, "unconfigured-v1");
            assertThrows(IllegalArgumentException.class, () -> service.register(new PublicationRequest(
                    new PkiId("publication-absent"), PublicationSourceType.CREDENTIAL,
                    credential.credentialId(), absent)));
            System.out.println("...registered states=" + first.status() + "," + statusRecord.status());
        }
        System.out.println("registrationRequiresCommittedExactSourceAndIsIdempotent...ok");
    }

    @Test
    void storeRejectsForeignContentAndObsoleteSidecarAuthority() throws Exception {
        System.out.println("storeRejectsForeignContentAndObsoleteSidecarAuthority");
        Path firstRoot = temporaryDirectory.resolve("foreign-first");
        Path secondRoot = temporaryDirectory.resolve("foreign-second");
        DurableContentReference foreign;
        try (FilesystemPkiStore second = new FilesystemPkiStore(secondRoot, FsPkiStoreOptions.defaults())) {
            foreign = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(second.stagedContent(), Encoding.DER,
                    new byte[] { 9, 9, 9 });
        }
        try (FilesystemPkiStore first = new FilesystemPkiStore(firstRoot, FsPkiStoreOptions.defaults())) {
            Credential credential = credential(first, "foreign", new byte[] { 1 });
            first.putCredential(credential);
            PublicationRecord invalid = pending("publication-foreign", credential, foreign);
            assertThrows(IllegalArgumentException.class, () -> first.createPublicationRecord(invalid));
        }
        Path obsolete = firstRoot.resolve("publications").resolve("by-id").resolve("legacy.bin");
        Files.createDirectories(obsolete.getParent());
        Files.write(obsolete, new byte[] { 1, 2 });
        assertThrows(IllegalStateException.class,
                () -> new FilesystemPkiStore(firstRoot, FsPkiStoreOptions.defaults()));
        assertArrayEquals(new byte[] { 1, 2 }, Files.readAllBytes(obsolete));
        System.out.println("storeRejectsForeignContentAndObsoleteSidecarAuthority...ok");
    }

    @Test
    void dispatchRetryAndTerminalStatesAreDurable() throws Exception {
        System.out.println("dispatchRetryAndTerminalStatesAreDurable");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore store = store("dispatch-states");
                DefaultPublicationService service = service(store, publisher)) {
            Credential credential = committedCredential(store, "retry", new byte[] { 1, 2, 3, 4 });
            PkiId operation = service.register(credentialRequest("publication-retry", credential)).publicationId();
            publisher.dispatchOutcome.set(PublicationOutcome.RETRYABLE_FAILURE);
            PublicationResult retryable = service.process(operation);
            PublicationRecord firstAttempt = service.find(operation).orElseThrow();
            String firstToken = firstAttempt.attemptToken().orElseThrow();
            assertEquals(PublicationStatus.RETRYABLE_FAILURE, retryable.status());
            assertEquals(1L, retryable.attemptNumber());

            publisher.dispatchOutcome.set(PublicationOutcome.SUCCESS);
            PublicationResult success = service.retry(operation);
            PublicationRecord secondAttempt = service.find(operation).orElseThrow();
            assertEquals(PublicationStatus.SUCCEEDED, success.status());
            assertEquals(2L, success.attemptNumber());
            assertNotEquals(firstToken, secondAttempt.attemptToken().orElseThrow());
            assertThrows(IllegalArgumentException.class, () -> service.retry(operation));
            assertThrows(IllegalArgumentException.class, () -> service.process(operation));

            Credential terminalCredential = committedCredential(store, "terminal", new byte[] { 5, 6 });
            PkiId terminalId = service.register(
                    credentialRequest("publication-terminal", terminalCredential)).publicationId();
            publisher.dispatchOutcome.set(PublicationOutcome.TERMINAL_FAILURE);
            assertEquals(PublicationStatus.TERMINAL_FAILURE, service.process(terminalId).status());
            assertThrows(IllegalArgumentException.class, () -> service.retry(terminalId));
            assertEquals(3, publisher.dispatchCalls.get());
            assertTrue(publisher.maximumReadSize.get() <= 11);
            System.out.println("...attempts=" + secondAttempt.attemptNumber());
        }
        System.out.println("dispatchRetryAndTerminalStatesAreDurable...ok");
    }

    @Test
    void publisherExceptionIsRedactedUnknownAndReconcilesWithSameToken() throws Exception {
        System.out.println("publisherExceptionIsRedactedUnknownAndReconcilesWithSameToken");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore store = store("unknown");
                DefaultPublicationService service = service(store, publisher)) {
            Credential credential = committedCredential(store, "unknown", new byte[] { 1, 3, 5 });
            PkiId operation = service.register(credentialRequest("publication-unknown", credential)).publicationId();
            publisher.throwOnDispatch.set(true);
            PublicationResult unknown = service.process(operation);
            PublicationRecord unknownRecord = service.find(operation).orElseThrow();
            String token = unknownRecord.attemptToken().orElseThrow();
            assertEquals(PublicationStatus.OUTCOME_UNKNOWN, unknown.status());
            assertEquals(Optional.of(PublicationFailure.EXTERNAL_OUTCOME_UNKNOWN), unknownRecord.failure());
            assertThrows(IllegalArgumentException.class, () -> service.process(operation));

            publisher.throwOnDispatch.set(false);
            PublicationResult unresolved = service.reconcile(operation);
            assertEquals(PublicationStatus.OUTCOME_UNKNOWN, unresolved.status());
            assertEquals(token, service.find(operation).orElseThrow().attemptToken().orElseThrow());

            publisher.reconciliationOutcome.set(Optional.of(PublicationOutcome.SUCCESS));
            PublicationResult resolved = service.reconcile(operation);
            assertEquals(PublicationStatus.SUCCEEDED, resolved.status());
            assertEquals(token, publisher.reconciliationAttempts.get(1).attemptToken());
            assertEquals(1, publisher.dispatchCalls.get());
            System.out.println("...token=" + token.substring(0, 12) + "...");
        }
        System.out.println("publisherExceptionIsRedactedUnknownAndReconcilesWithSameToken...ok");
    }

    @Test
    void resultPersistenceFailureFencesUnknownAndCommittedUncertaintyResolves() throws Exception {
        System.out.println("resultPersistenceFailureFencesUnknownAndCommittedUncertaintyResolves");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore store = store("persistence-failure");
                DefaultPublicationService service = service(store, publisher)) {
            Credential first = committedCredential(store, "persist-first", new byte[] { 1 });
            PkiId firstId = service.register(credentialRequest("publication-persist-first", first)).publicationId();
            publisher.afterDispatch = () -> FilesystemPkiStore.installPublicationCommitFault(
                    FilesystemPkiStore.PublicationCommitFaultPoint.REPLACE_BEFORE_COMMIT);
            PkiException failure = assertThrows(PkiException.class, () -> service.process(firstId));
            assertTrue(failure.getMessage().contains("code=PUBLICATION_RESULT_UNCONFIRMED"));
            PublicationRecord unknown = service.find(firstId).orElseThrow();
            assertEquals(PublicationStatus.OUTCOME_UNKNOWN, unknown.status());
            assertEquals(Optional.of(PublicationFailure.RESULT_PERSISTENCE_UNKNOWN), unknown.failure());

            Credential second = committedCredential(store, "persist-second", new byte[] { 2 });
            PkiId secondId = service.register(
                    credentialRequest("publication-persist-second", second)).publicationId();
            publisher.afterDispatch = () -> FilesystemPkiStore.installPublicationCommitFault(
                    FilesystemPkiStore.PublicationCommitFaultPoint.REPLACE_COMMIT_AS_UNKNOWN);
            PublicationResult resolved = service.process(secondId);
            assertEquals(PublicationStatus.SUCCEEDED, resolved.status());
            assertEquals(PublicationStatus.SUCCEEDED, service.find(secondId).orElseThrow().status());

            Credential third = committedCredential(store, "persist-third", new byte[] { 3 });
            FilesystemPkiStore.installPublicationCommitFault(
                    FilesystemPkiStore.PublicationCommitFaultPoint.CREATE_BEFORE_COMMIT);
            assertThrows(IllegalStateException.class,
                    () -> service.register(credentialRequest("publication-create-failure", third)));
            assertTrue(service.find(new PkiId("publication-create-failure")).isEmpty());
            System.out.println("...unknown failure=" + unknown.failure().orElseThrow());
        }
        System.out.println("resultPersistenceFailureFencesUnknownAndCommittedUncertaintyResolves...ok");
    }

    @Test
    void restartConvertsPreparedAttemptToUnknownWithoutDispatch() throws Exception {
        System.out.println("restartConvertsPreparedAttemptToUnknownWithoutDispatch");
        Path root = temporaryDirectory.resolve("restart");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        PkiId operation = new PkiId("publication-restart");
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                DefaultPublicationService service = service(store, publisher)) {
            Credential credential = committedCredential(store, "restart", new byte[] { 4, 4 });
            PublicationRecord pending = service.register(new PublicationRequest(operation,
                    PublicationSourceType.CREDENTIAL, credential.credentialId(), TARGET));
            PublicationRecord prepared = new PublicationRecord(pending.publicationId(), pending.sourceType(),
                    pending.sourceId(), pending.content(), pending.target(), PublicationStatus.DISPATCH_PREPARED,
                    1L, Optional.of("a".repeat(64)), pending.createdAt(), pending.updatedAt(), Optional.empty(),
                    Optional.empty());
            assertTrue(store.replacePublicationRecord(pending, prepared));
        }
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults())) {
            PublicationRecord record = reopened.getPublicationRecord(operation).orElseThrow();
            assertEquals(PublicationStatus.OUTCOME_UNKNOWN, record.status());
            assertEquals("a".repeat(64), record.attemptToken().orElseThrow());
            assertEquals(0, publisher.dispatchCalls.get());
            try (DefaultPublicationService recovered = service(reopened, publisher)) {
                assertEquals(PublicationStatus.OUTCOME_UNKNOWN,
                        recovered.find(operation).orElseThrow().status());
            }
        }
        System.out.println("restartConvertsPreparedAttemptToUnknownWithoutDispatch...ok");
    }

    @Test
    void restartPreservesPendingRetryableSuccessfulAndUnknownStates() throws Exception {
        System.out.println("restartPreservesPendingRetryableSuccessfulAndUnknownStates");
        Path root = temporaryDirectory.resolve("restart-states");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore store = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                DefaultPublicationService service = service(store, publisher)) {
            Credential pending = committedCredential(store, "restart-pending", new byte[] { 1 });
            Credential retryable = committedCredential(store, "restart-retryable", new byte[] { 2 });
            Credential succeeded = committedCredential(store, "restart-succeeded", new byte[] { 3 });
            Credential unknown = committedCredential(store, "restart-unknown", new byte[] { 4 });
            service.register(credentialRequest("publication-restart-pending", pending));
            service.register(credentialRequest("publication-restart-retryable", retryable));
            service.register(credentialRequest("publication-restart-succeeded", succeeded));
            service.register(credentialRequest("publication-restart-unknown", unknown));
            publisher.dispatchOutcome.set(PublicationOutcome.RETRYABLE_FAILURE);
            service.process(new PkiId("publication-restart-retryable"));
            publisher.dispatchOutcome.set(PublicationOutcome.SUCCESS);
            service.process(new PkiId("publication-restart-succeeded"));
            publisher.throwOnDispatch.set(true);
            service.process(new PkiId("publication-restart-unknown"));
        }
        RecordingPublisher reopenedPublisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore reopened = new FilesystemPkiStore(root, FsPkiStoreOptions.defaults());
                DefaultPublicationService recovered = service(reopened, reopenedPublisher)) {
            assertEquals(PublicationStatus.PENDING,
                    recovered.find(new PkiId("publication-restart-pending")).orElseThrow().status());
            assertEquals(PublicationStatus.RETRYABLE_FAILURE,
                    recovered.find(new PkiId("publication-restart-retryable")).orElseThrow().status());
            assertEquals(PublicationStatus.SUCCEEDED,
                    recovered.find(new PkiId("publication-restart-succeeded")).orElseThrow().status());
            assertEquals(PublicationStatus.OUTCOME_UNKNOWN,
                    recovered.find(new PkiId("publication-restart-unknown")).orElseThrow().status());
            assertEquals(0, reopenedPublisher.dispatchCalls.get());
            assertTrue(reopened.getCredential(new PkiId("credential:restart-unknown")).isPresent());
            System.out.println("...recovered states=4");
        }
        System.out.println("restartPreservesPendingRetryableSuccessfulAndUnknownStates...ok");
    }

    @Test
    void concurrentSameOperationDoesNotDuplicateAndUnrelatedProgresses() throws Exception {
        System.out.println("concurrentSameOperationDoesNotDuplicateAndUnrelatedProgresses");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        publisher.blockedPublication.set(new PkiId("publication-blocked"));
        try (FilesystemPkiStore store = store("concurrency")) {
            DefaultPublicationService service = service(store, publisher);
            try (service) {
                try (ExecutorService executor = Executors.newFixedThreadPool(2)) {
                    Credential blocked = committedCredential(store, "blocked", new byte[] { 1, 2 });
                    Credential unrelated = committedCredential(store, "unrelated", new byte[] { 3, 4 });
                    service.register(credentialRequest("publication-blocked", blocked));
                    service.register(credentialRequest("publication-unrelated", unrelated));

                    Future<PublicationResult> first = executor.submit(
                            () -> service.process(new PkiId("publication-blocked")));
                    assertTrue(publisher.entered.await(5, TimeUnit.SECONDS));
                    assertThrows(IllegalArgumentException.class,
                            () -> service.process(new PkiId("publication-blocked")));
                    Future<PublicationResult> second = executor.submit(
                            () -> service.process(new PkiId("publication-unrelated")));
                    assertEquals(PublicationStatus.SUCCEEDED, second.get(5, TimeUnit.SECONDS).status());
                    service.close();
                    assertThrows(IllegalStateException.class,
                            () -> service.find(new PkiId("publication-unrelated")));
                    publisher.release.countDown();
                    assertEquals(PublicationStatus.SUCCEEDED, first.get(5, TimeUnit.SECONDS).status());
                    assertEquals(2, publisher.dispatchCalls.get());
                    System.out.println("...dispatch calls=" + publisher.dispatchCalls.get());
                }
            }
        }
        System.out.println("concurrentSameOperationDoesNotDuplicateAndUnrelatedProgresses...ok");
    }

    @Test
    void secondServiceDoesNotReclassifyAnActiveDispatch() throws Exception {
        System.out.println("secondServiceDoesNotReclassifyAnActiveDispatch");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        PkiId operation = new PkiId("publication-two-services");
        publisher.blockedPublication.set(operation);
        try (FilesystemPkiStore store = store("two-services");
                DefaultPublicationService first = service(store, publisher);
                ExecutorService executor = Executors.newSingleThreadExecutor()) {
            Credential credential = committedCredential(store, "two-services", new byte[] { 7, 7 });
            first.register(new PublicationRequest(operation, PublicationSourceType.CREDENTIAL,
                    credential.credentialId(), TARGET));
            Future<PublicationResult> result = executor.submit(() -> first.process(operation));
            assertTrue(publisher.entered.await(5L, TimeUnit.SECONDS));
            try (DefaultPublicationService second = service(store, publisher)) {
                assertEquals(PublicationStatus.DISPATCH_PREPARED,
                        second.find(operation).orElseThrow().status());
                assertThrows(IllegalArgumentException.class, () -> second.reconcile(operation));
            }
            publisher.release.countDown();
            assertEquals(PublicationStatus.SUCCEEDED, result.get(5L, TimeUnit.SECONDS).status());
            assertEquals(1, publisher.dispatchCalls.get());
            System.out.println("...active state preserved");
        }
        System.out.println("secondServiceDoesNotReclassifyAnActiveDispatch...ok");
    }

    @Test
    void cursorIsStableFilteredAndCloseable() throws Exception {
        System.out.println("cursorIsStableFilteredAndCloseable");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore store = store("cursor");
                DefaultPublicationService service = service(store, publisher)) {
            Credential credential = committedCredential(store, "cursor-credential", new byte[] { 1 });
            StatusObject status = status(store, "cursor-status", new byte[] { 2 });
            store.putStatusObject(status);
            service.register(credentialRequest("publication-cursor-credential", credential));
            PublicationCursor cursor = service.openPublications(new PublicationQuery(Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.of(PublicationSourceType.STATUS_OBJECT)));
            service.register(statusRequest("publication-cursor-status", status));
            assertTrue(cursor.next(CancellationSignal.NONE).isEmpty());
            cursor.close();
            assertThrows(IllegalStateException.class, () -> cursor.next(CancellationSignal.NONE));

            try (PublicationCursor current = service.openPublications(new PublicationQuery(Optional.empty(),
                    Optional.empty(), Optional.empty(), Optional.of(PublicationSourceType.STATUS_OBJECT)))) {
                assertEquals(new PkiId("publication-cursor-status"),
                        current.next(CancellationSignal.NONE).orElseThrow().publicationId());
                assertTrue(current.next(CancellationSignal.NONE).isEmpty());
            }
        }
        System.out.println("cursorIsStableFilteredAndCloseable...ok");
    }

    @Test
    void snapshotReconstructsPublicationMetadataWithoutSidecarAuthority() throws Exception {
        System.out.println("snapshotReconstructsPublicationMetadataWithoutSidecarAuthority");
        Path sourceRoot = temporaryDirectory.resolve("snapshot-source");
        Path snapshotRoot = temporaryDirectory.resolve("snapshot-target");
        RecordingPublisher publisher = new RecordingPublisher(TARGET);
        PkiId operation = new PkiId("publication-snapshot");
        String sourceContentId;
        try (FilesystemPkiStore source = new FilesystemPkiStore(sourceRoot, FsPkiStoreOptions.defaults());
                DefaultPublicationService service = service(source, publisher)) {
            Credential credential = committedCredential(source, "snapshot", new byte[] { 8, 6, 7, 5 });
            sourceContentId = credential.content().contentId();
            service.register(new PublicationRequest(operation, PublicationSourceType.CREDENTIAL,
                    credential.credentialId(), TARGET));
            assertEquals(PublicationStatus.SUCCEEDED, service.process(operation).status());
            source.exportSnapshot(snapshotRoot, NOW.plusSeconds(1L));
        }
        assertFalse(Files.exists(snapshotRoot.resolve("publications")));
        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshotRoot, FsPkiStoreOptions.defaults())) {
            PublicationRecord record = restored.getPublicationRecord(operation).orElseThrow();
            assertEquals(PublicationStatus.SUCCEEDED, record.status());
            assertNotEquals(sourceContentId, record.content().contentId());
            assertEquals(restored.getCredential(record.sourceId()).orElseThrow().content(), record.content());
        }
        System.out.println("snapshotReconstructsPublicationMetadataWithoutSidecarAuthority...ok");
    }

    @Test
    void snapshotRemintingPreservesPendingAndRetryAttemptTokens() throws Exception {
        System.out.println("snapshotRemintingPreservesPendingAndRetryAttemptTokens");
        Path sourceRoot = temporaryDirectory.resolve("snapshot-token-source");
        Path snapshotRoot = temporaryDirectory.resolve("snapshot-token-target");
        PkiId pendingId = new PkiId("publication-snapshot-pending-token");
        PkiId retryId = new PkiId("publication-snapshot-retry-token");
        RecordingPublisher sourcePublisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore source = new FilesystemPkiStore(sourceRoot, FsPkiStoreOptions.defaults());
                DefaultPublicationService service = service(source, sourcePublisher)) {
            Credential pending = committedCredential(source, "snapshot-pending-token", new byte[] { 1, 4 });
            Credential retryable = committedCredential(source, "snapshot-retry-token", new byte[] { 2, 8 });
            service.register(new PublicationRequest(pendingId, PublicationSourceType.CREDENTIAL,
                    pending.credentialId(), TARGET));
            service.register(new PublicationRequest(retryId, PublicationSourceType.CREDENTIAL,
                    retryable.credentialId(), TARGET));
            sourcePublisher.dispatchOutcome.set(PublicationOutcome.RETRYABLE_FAILURE);
            service.process(retryId);
            source.exportSnapshot(snapshotRoot, NOW.plusSeconds(1L));

            sourcePublisher.dispatchOutcome.set(PublicationOutcome.SUCCESS);
            service.process(pendingId);
            service.retry(retryId);
        }

        RecordingPublisher restoredPublisher = new RecordingPublisher(TARGET);
        try (FilesystemPkiStore restored = new FilesystemPkiStore(snapshotRoot, FsPkiStoreOptions.defaults());
                DefaultPublicationService service = service(restored, restoredPublisher)) {
            service.process(pendingId);
            service.retry(retryId);
        }
        assertEquals(attemptToken(sourcePublisher, pendingId, 1L),
                attemptToken(restoredPublisher, pendingId, 1L));
        assertEquals(attemptToken(sourcePublisher, retryId, 2L),
                attemptToken(restoredPublisher, retryId, 2L));
        System.out.println("...snapshot-stable tokens=2");
        System.out.println("snapshotRemintingPreservesPendingAndRetryAttemptTokens...ok");
    }

    @Test
    void strictCodecRejectsTrailingAndImpossiblePublicationMetadata() throws Exception {
        System.out.println("strictCodecRejectsTrailingAndImpossiblePublicationMetadata");
        try (FilesystemPkiStore store = store("codec")) {
            Credential credential = committedCredential(store, "codec", new byte[] { 1, 2 });
            PublicationRecord record = pending("publication-codec", credential, credential.content());
            byte[] encoded = PublicationRecordCodec.encode(record);
            byte[] trailing = java.util.Arrays.copyOf(encoded, encoded.length + 1);
            assertThrows(IOException.class, () -> PublicationRecordCodec.decode(trailing, store.stagedContent()));
            encoded[0] ^= 0x01;
            assertThrows(IOException.class, () -> PublicationRecordCodec.decode(encoded, store.stagedContent()));
        }
        System.out.println("strictCodecRejectsTrailingAndImpossiblePublicationMetadata...ok");
    }

    private FilesystemPkiStore store(String suffix) {
        return new FilesystemPkiStore(temporaryDirectory.resolve(suffix), FsPkiStoreOptions.defaults());
    }

    private static DefaultPublicationService service(FilesystemPkiStore store, Publisher publisher) {
        return new DefaultPublicationService(store, CLOCK, List.of(publisher));
    }

    private static Credential committedCredential(FilesystemPkiStore store, String suffix, byte[] bytes)
            throws IOException {
        Credential credential = credential(store, suffix, bytes);
        store.putCredential(credential);
        return credential;
    }

    private static Credential credential(FilesystemPkiStore store, String suffix, byte[] bytes) throws IOException {
        DurableContentReference content = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                store.stagedContent(), Encoding.DER, bytes);
        return new Credential(new PkiId("credential:" + suffix), new FormatId("publication-test-binary"),
                new IssuerRef(new PkiId("ca:publication")), new SubjectRef("CN=" + suffix),
                new Validity(NOW.minusSeconds(60L), NOW.plusSeconds(3600L)), suffix,
                new PkiId("key:" + suffix),
                new CaProfileBinding(new zeroecho.pki.api.profile.CertificateProfileRef(
                        "default", 1L, new byte[32])), CredentialStatus.ISSUED, content, new SimpleAttributeSet());
    }

    private static StatusObject status(FilesystemPkiStore store, String suffix, byte[] bytes) throws IOException {
        DurableContentReference content = zeroecho.pki.testkit.PkiTestRuntime.fixtureReference(
                store.stagedContent(), Encoding.DER, bytes);
        return new StatusObject(new PkiId("status:" + suffix), new FormatId("x509"),
                new PkiId("ca:publication"), StatusObjectType.CRL, NOW, Optional.of(NOW.plusSeconds(60L)),
                content, new SimpleAttributeSet());
    }

    private static PublicationRequest credentialRequest(String publicationId, Credential credential) {
        return new PublicationRequest(new PkiId(publicationId), PublicationSourceType.CREDENTIAL,
                credential.credentialId(), TARGET);
    }

    private static PublicationRequest statusRequest(String publicationId, StatusObject status) {
        return new PublicationRequest(new PkiId(publicationId), PublicationSourceType.STATUS_OBJECT,
                status.statusObjectId(), TARGET);
    }

    private static PublicationRecord pending(String publicationId, Credential credential,
            DurableContentReference content) {
        return new PublicationRecord(new PkiId(publicationId), PublicationSourceType.CREDENTIAL,
                credential.credentialId(), content, TARGET, PublicationStatus.PENDING, 0L, Optional.empty(),
                NOW, NOW, Optional.empty(), Optional.empty());
    }

    private static String attemptToken(RecordingPublisher publisher, PkiId publicationId, long attemptNumber) {
        return publisher.dispatchAttempts.stream()
                .filter(attempt -> attempt.publicationId().equals(publicationId)
                        && attempt.attemptNumber() == attemptNumber)
                .findFirst().orElseThrow().attemptToken();
    }

    /** Deterministic streaming publisher with controllable outcomes and barriers. */
    private static final class RecordingPublisher implements Publisher {
        private final PublicationTarget target;
        private final AtomicInteger dispatchCalls = new AtomicInteger();
        private final AtomicInteger maximumReadSize = new AtomicInteger();
        private final AtomicReference<PublicationOutcome> dispatchOutcome =
                new AtomicReference<>(PublicationOutcome.SUCCESS);
        private final AtomicReference<Optional<PublicationOutcome>> reconciliationOutcome =
                new AtomicReference<>(Optional.empty());
        private final AtomicBoolean throwOnDispatch = new AtomicBoolean();
        private final List<PublicationAttempt> reconciliationAttempts = java.util.Collections.synchronizedList(
                new ArrayList<>());
        private final List<PublicationAttempt> dispatchAttempts = java.util.Collections.synchronizedList(
                new ArrayList<>());
        private final AtomicReference<PkiId> blockedPublication = new AtomicReference<>();
        private final CountDownLatch entered = new CountDownLatch(1);
        private final CountDownLatch release = new CountDownLatch(1);
        private volatile Runnable afterDispatch = () -> { };

        private RecordingPublisher(PublicationTarget target) {
            this.target = target;
        }

        @Override
        public PublicationTarget target() {
            return target;
        }

        @Override
        public PublicationOutcome publish(PublicationAttempt attempt, RepeatableContent payload) {
            dispatchCalls.incrementAndGet();
            dispatchAttempts.add(attempt);
            try (InputStream input = payload.openStream()) {
                byte[] buffer = new byte[11];
                while (true) {
                    int count = input.read(buffer);
                    if (count < 0) {
                        break;
                    }
                    maximumReadSize.accumulateAndGet(count, Math::max);
                }
                if (attempt.publicationId().equals(blockedPublication.get())) {
                    entered.countDown();
                    if (!release.await(5L, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("publisher barrier timeout");
                    }
                }
            } catch (IOException exception) {
                throw new IllegalStateException("provider-secret-path", exception);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("provider-secret-interrupted", exception);
            }
            if (throwOnDispatch.get()) {
                throw new IllegalStateException("provider-secret-token-and-path");
            }
            afterDispatch.run();
            afterDispatch = () -> { };
            return dispatchOutcome.get();
        }

        @Override
        public Optional<PublicationOutcome> reconcile(PublicationAttempt attempt) {
            reconciliationAttempts.add(attempt);
            return reconciliationOutcome.get();
        }
    }
}
