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
package zeroecho.pki.impl.core;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.Collection;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.PkiFailureReason;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.content.DurableContentReference;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.publication.PublicationCursor;
import zeroecho.pki.api.publication.PublicationEvidence;
import zeroecho.pki.api.publication.PublicationFailure;
import zeroecho.pki.api.publication.PublicationQuery;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.publication.PublicationRequest;
import zeroecho.pki.api.publication.PublicationResult;
import zeroecho.pki.api.publication.PublicationSourceType;
import zeroecho.pki.api.publication.PublicationStatus;
import zeroecho.pki.api.publication.PublicationTarget;
import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.spi.publish.PublicationAttempt;
import zeroecho.pki.spi.publish.PublicationOutcome;
import zeroecho.pki.spi.publish.Publisher;
import zeroecho.pki.spi.store.PkiStore;

/**
 * Durable explicit post-commit publication lifecycle.
 *
 * <p>The service is thread-safe. Each external call is fenced by a durable
 * compare-and-replace transition and occurs without a metadata transaction or
 * store lock. Operations for unrelated identities progress independently. The
 * service creates no threads and performs no automatic dispatch or retry.</p>
 */
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.AvoidCatchingGenericException",
        "PMD.PreserveStackTrace", "PMD.ExceptionAsFlowControl" })
public final class DefaultPublicationService implements PublicationService {
    private final PkiStore store;
    private final Clock clock;
    private final Map<PublicationTarget, Publisher> publishers;
    private final AtomicBoolean closed = new AtomicBoolean();

    /**
     * Opens a publication lifecycle over one store and immutable publisher registry.
     *
     * <p>Opening validates a stable publication snapshot and all configured target
     * bindings. The supplied store must already have performed its exclusive-open
     * recovery of abandoned dispatch-prepared attempts. Construction never calls
     * an external publisher.</p>
     *
     * @param store authoritative PKI store
     * @param clock operational state-change clock
     * @param publishers configured publisher instances with unique targets
     * @throws IllegalArgumentException if a publisher target is duplicated
     * @throws PkiException if durable publication recovery fails closed
     */
    public DefaultPublicationService(PkiStore store, Clock clock, Collection<? extends Publisher> publishers) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(publishers, "publishers");
        Map<PublicationTarget, Publisher> configured = new HashMap<>();
        for (Publisher publisher : publishers) {
            Publisher exact = Objects.requireNonNull(publisher, "publisher");
            PublicationTarget target;
            try {
                target = Objects.requireNonNull(exact.target(), "publisher.target");
            } catch (RuntimeException failure) {
                throw new IllegalArgumentException("Publication publisher configuration is invalid");
            }
            if (configured.putIfAbsent(target, exact) != null) {
                throw new IllegalArgumentException("Publication target is configured more than once");
            }
        }
        this.publishers = Map.copyOf(configured);
        validateConfiguredOperations();
    }

    @Override
    public PublicationRecord register(PublicationRequest request) {
        requireOpen();
        Objects.requireNonNull(request, "request");
        requirePublisher(request.target());
        DurableContentReference content = resolveSourceContent(request.sourceType(), request.sourceId());
        validateContent(content);
        Optional<PublicationRecord> existing = store.getPublicationRecord(request.publicationId());
        if (existing.isPresent()) {
            PublicationRecord current = existing.orElseThrow();
            if (current.sourceType() == request.sourceType() && current.sourceId().equals(request.sourceId())
                    && current.target().equals(request.target()) && sameContent(current.content(), content)) {
                return current;
            }
            throw new IllegalArgumentException("Publication identity conflicts with an existing operation");
        }
        Instant now = clock.instant();
        PublicationRecord pending = new PublicationRecord(request.publicationId(), request.sourceType(),
                request.sourceId(), content, request.target(), PublicationStatus.PENDING, 0L, Optional.empty(),
                now, now, Optional.empty(), Optional.empty());
        return store.createPublicationRecord(pending);
    }

    @Override
    public PublicationResult process(PkiId publicationId) {
        requireOpen();
        PublicationRecord pending = requireRecord(publicationId);
        if (pending.status() != PublicationStatus.PENDING) {
            throw new IllegalArgumentException("Publication operation is not pending");
        }
        long attemptNumber;
        try {
            attemptNumber = Math.addExact(pending.attemptNumber(), 1L);
        } catch (ArithmeticException overflow) {
            throw new PkiException("Publication attempt counter is exhausted: code=PUBLICATION_ATTEMPT_EXHAUSTED",
                    PkiFailureReason.PUBLICATION_ATTEMPT_EXHAUSTED);
        }
        String token = attemptToken(pending, attemptNumber);
        PublicationRecord prepared = copy(pending, PublicationStatus.DISPATCH_PREPARED, attemptNumber,
                Optional.of(token), Optional.empty(), Optional.empty());
        if (!store.replacePublicationRecord(pending, prepared)) {
            throw new PkiException("Publication operation changed concurrently: code=PUBLICATION_CONCURRENT_MODIFICATION",
                    PkiFailureReason.PUBLICATION_CONCURRENT_MODIFICATION);
        }
        return dispatchPrepared(prepared, PublicationEvidence.DIRECT_RESPONSE, false);
    }

    @Override
    public PublicationResult retry(PkiId publicationId) {
        requireOpen();
        PublicationRecord failed = requireRecord(publicationId);
        if (failed.status() != PublicationStatus.RETRYABLE_FAILURE) {
            throw new IllegalArgumentException("Publication operation is not retryable");
        }
        PublicationRecord pending = copy(failed, PublicationStatus.PENDING, failed.attemptNumber(),
                Optional.empty(), Optional.empty(), Optional.empty());
        if (!store.replacePublicationRecord(failed, pending)) {
            throw new PkiException("Publication operation changed concurrently: code=PUBLICATION_CONCURRENT_MODIFICATION",
                    PkiFailureReason.PUBLICATION_CONCURRENT_MODIFICATION);
        }
        return process(publicationId);
    }

    @Override
    public PublicationResult reconcile(PkiId publicationId) {
        requireOpen();
        PublicationRecord unknown = requireRecord(publicationId);
        if (unknown.status() != PublicationStatus.OUTCOME_UNKNOWN) {
            throw new IllegalArgumentException("Publication operation does not require reconciliation");
        }
        PublicationRecord prepared = copy(unknown, PublicationStatus.DISPATCH_PREPARED, unknown.attemptNumber(),
                unknown.attemptToken(), Optional.empty(), Optional.empty());
        if (!store.replacePublicationRecord(unknown, prepared)) {
            throw new PkiException("Publication operation changed concurrently: code=PUBLICATION_CONCURRENT_MODIFICATION",
                    PkiFailureReason.PUBLICATION_CONCURRENT_MODIFICATION);
        }
        return dispatchPrepared(prepared, PublicationEvidence.RECONCILIATION_RESPONSE, true);
    }

    @Override
    public Optional<PublicationRecord> find(PkiId publicationId) {
        requireOpen();
        return store.getPublicationRecord(Objects.requireNonNull(publicationId, "publicationId"));
    }

    @Override
    public PublicationCursor openPublications(PublicationQuery query) {
        requireOpen();
        return new FilteringCursor(store.openPublicationRecords(), Objects.requireNonNull(query, "query"));
    }

    @Override
    public void close() {
        closed.set(true);
    }

    private PublicationResult dispatchPrepared(PublicationRecord prepared, PublicationEvidence evidence,
            boolean reconciliation) {
        Publisher publisher = requirePublisher(prepared.target());
        PublicationAttempt attempt = attempt(prepared);
        if (!reconciliation) {
            try {
                validateContent(prepared.content());
            } catch (PkiException failure) {
                PublicationRecord terminal = copy(prepared, PublicationStatus.TERMINAL_FAILURE,
                        prepared.attemptNumber(), prepared.attemptToken(),
                        Optional.of(PublicationFailure.CONTENT_INVALID), Optional.empty());
                return persistResult(prepared, terminal);
            }
        }

        Optional<PublicationOutcome> outcome;
        if (reconciliation) {
            outcome = reconcileExternal(publisher, attempt);
            if (outcome.isEmpty()) {
                PublicationRecord unresolved = copy(prepared, PublicationStatus.OUTCOME_UNKNOWN,
                        prepared.attemptNumber(), prepared.attemptToken(),
                        Optional.of(PublicationFailure.EXTERNAL_OUTCOME_UNKNOWN), Optional.empty());
                return persistResult(prepared, unresolved);
            }
        } else {
            outcome = dispatchExternal(publisher, attempt, prepared);
            if (outcome.isEmpty()) {
                PublicationRecord unknown = copy(prepared, PublicationStatus.OUTCOME_UNKNOWN,
                        prepared.attemptNumber(), prepared.attemptToken(),
                        Optional.of(PublicationFailure.EXTERNAL_OUTCOME_UNKNOWN), Optional.empty());
                return persistResult(prepared, unknown);
            }
        }
        PublicationRecord classified = classified(prepared, outcome.orElseThrow(), evidence);
        return persistResult(prepared, classified);
    }

    private Optional<PublicationOutcome> dispatchExternal(Publisher publisher, PublicationAttempt attempt,
            PublicationRecord prepared) {
        try (RepeatableContent payload = store.stagedContent().openContent(prepared.content())) {
            return Optional.of(Objects.requireNonNull(publisher.publish(attempt, payload), "publisher outcome"));
        } catch (IOException | RuntimeException failure) {
            return Optional.empty();
        }
    }

    private static Optional<PublicationOutcome> reconcileExternal(Publisher publisher, PublicationAttempt attempt) {
        try {
            return Objects.requireNonNull(publisher.reconcile(attempt), "publisher reconciliation outcome");
        } catch (RuntimeException failure) {
            return Optional.empty();
        }
    }

    private PublicationResult persistResult(PublicationRecord prepared, PublicationRecord classified) {
        try {
            if (store.replacePublicationRecord(prepared, classified)) {
                return result(classified);
            }
            PublicationRecord observed = requireRecord(prepared.publicationId());
            if (observed.status() != PublicationStatus.DISPATCH_PREPARED) {
                return result(observed);
            }
        } catch (RuntimeException persistenceFailure) {
            Optional<PublicationRecord> observed = safeFind(prepared.publicationId());
            if (observed.isPresent() && observed.orElseThrow().status() != PublicationStatus.DISPATCH_PREPARED) {
                return result(observed.orElseThrow());
            }
        }
        PublicationRecord unknown = copy(prepared, PublicationStatus.OUTCOME_UNKNOWN, prepared.attemptNumber(),
                prepared.attemptToken(), Optional.of(PublicationFailure.RESULT_PERSISTENCE_UNKNOWN), Optional.empty());
        try {
            store.replacePublicationRecord(prepared, unknown);
        } catch (RuntimeException ignored) {
            // The durable PREPARED fence remains non-dispatchable and is converted
            // to OUTCOME_UNKNOWN during the next service recovery.
        }
        throw new PkiException(
                "Publication result persistence requires reconciliation: code=PUBLICATION_RESULT_UNCONFIRMED",
                PkiFailureReason.PUBLICATION_RESULT_UNCONFIRMED);
    }

    private Optional<PublicationRecord> safeFind(PkiId publicationId) {
        try {
            return store.getPublicationRecord(publicationId);
        } catch (RuntimeException ignored) {
            return Optional.empty();
        }
    }

    private void validateConfiguredOperations() {
        try (PublicationCursor cursor = store.openPublicationRecords()) {
            Optional<PublicationRecord> next;
            while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                PublicationRecord record = next.orElseThrow();
                requirePublisher(record.target());
            }
        } catch (IOException | RuntimeException failure) {
            throw publicationRecoveryFailure();
        }
    }

    private DurableContentReference resolveSourceContent(PublicationSourceType type, PkiId sourceId) {
        Objects.requireNonNull(type, "sourceType");
        Objects.requireNonNull(sourceId, "sourceId");
        return switch (type) {
            case CREDENTIAL -> store.getCredential(sourceId).map(Credential::content)
                    .orElseThrow(() -> new IllegalArgumentException("Publication credential is not committed"));
            case STATUS_OBJECT -> store.getStatusObject(sourceId).map(StatusObject::content)
                    .orElseThrow(() -> new IllegalArgumentException("Publication status object is not committed"));
        };
    }

    /**
     * Releases an eagerly verified stream, preserving nullable resource ownership.
     * @param verified stream opened for verification, or null when no stream was returned
     * @throws IOException if closing the opened stream fails
     */
    private static void close(java.io.InputStream verified) throws IOException {
        if (verified != null) {
            verified.close();
        }
    }

    private void validateContent(DurableContentReference reference) {
        try {
            DurableContentReference exact = store.stagedContent().restoreReference(reference.storeId(),
                    reference.contentId(), reference.encoding(), reference.length(), reference.sha256(),
                    reference.lifecycle());
            if (!sameContent(reference, exact)) {
                throw new IOException("Publication content commitment mismatch");
            }
            try (RepeatableContent content = store.stagedContent().openContent(exact)) {
                // Opening the store-issued stream performs the complete immutable
                // integrity check before any publisher callback can run.
                close(content.openStream());
            }
        } catch (IOException | RuntimeException failure) {
            throw new PkiException("Publication content is invalid: code=PUBLICATION_CONTENT_INVALID",
                PkiFailureReason.PUBLICATION_CONTENT_INVALID);
        }
    }

    private Publisher requirePublisher(PublicationTarget target) {
        Publisher publisher = publishers.get(Objects.requireNonNull(target, "target"));
        if (publisher == null) {
            throw new IllegalArgumentException("Publication target is not configured");
        }
        return publisher;
    }

    private PublicationRecord requireRecord(PkiId publicationId) {
        return store.getPublicationRecord(Objects.requireNonNull(publicationId, "publicationId"))
                .orElseThrow(() -> new PkiException("Publication operation does not exist: code=PUBLICATION_NOT_FOUND",
                        PkiFailureReason.PUBLICATION_NOT_FOUND));
    }

    private PublicationRecord copy(PublicationRecord current, PublicationStatus status, long attemptNumber,
            Optional<String> token, Optional<PublicationFailure> failure, Optional<PublicationEvidence> evidence) {
        Instant updatedAt = clock.instant();
        if (updatedAt.isBefore(current.updatedAt())) {
            updatedAt = current.updatedAt();
        }
        return new PublicationRecord(current.publicationId(), current.sourceType(), current.sourceId(),
                current.content(), current.target(), status, attemptNumber, token, current.createdAt(), updatedAt,
                failure, evidence);
    }

    private PublicationRecord classified(PublicationRecord prepared, PublicationOutcome outcome,
            PublicationEvidence evidence) {
        return switch (outcome) {
            case SUCCESS -> copy(prepared, PublicationStatus.SUCCEEDED, prepared.attemptNumber(),
                    prepared.attemptToken(), Optional.empty(), Optional.of(evidence));
            case RETRYABLE_FAILURE -> copy(prepared, PublicationStatus.RETRYABLE_FAILURE, prepared.attemptNumber(),
                    prepared.attemptToken(), Optional.of(PublicationFailure.EXTERNAL_RETRYABLE),
                    Optional.of(evidence));
            case TERMINAL_FAILURE -> copy(prepared, PublicationStatus.TERMINAL_FAILURE, prepared.attemptNumber(),
                    prepared.attemptToken(), Optional.of(PublicationFailure.EXTERNAL_TERMINAL),
                    Optional.of(evidence));
        };
    }

    private static PublicationAttempt attempt(PublicationRecord prepared) {
        DurableContentReference content = prepared.content();
        return new PublicationAttempt(prepared.publicationId(), prepared.sourceType(), prepared.sourceId(),
                prepared.target(), prepared.attemptNumber(), prepared.attemptToken().orElseThrow(),
                content.encoding(), content.length(), content.sha256());
    }

    private static PublicationResult result(PublicationRecord record) {
        return new PublicationResult(record.publicationId(), record.status(), record.attemptNumber());
    }

    private static String attemptToken(PublicationRecord record, long attemptNumber) {
        MessageDigest digest = sha256();
        update(digest, record.publicationId().value());
        update(digest, record.sourceType().name());
        update(digest, record.sourceId().value());
        update(digest, record.target().type().name());
        update(digest, record.target().targetId());
        update(digest, record.content().encoding().name());
        update(digest, record.content().sha256());
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(record.content().length()).array());
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(attemptNumber).array());
        return HexFormat.of().formatHex(digest.digest());
    }

    private static void update(MessageDigest digest, String value) {
        byte[] encoded = value.getBytes(StandardCharsets.UTF_8);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(encoded.length).array());
        digest.update(encoded);
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static boolean sameContent(DurableContentReference first, DurableContentReference second) {
        return first.storeId().equals(second.storeId()) && first.contentId().equals(second.contentId())
                && first.encoding() == second.encoding() && first.length() == second.length()
                && first.sha256().equals(second.sha256()) && first.lifecycle() == second.lifecycle();
    }

    private void requireOpen() {
        if (closed.get()) {
            throw new IllegalStateException("Publication service is closed");
        }
    }

    private static PkiException publicationRecoveryFailure() {
        return new PkiException("Publication recovery failed: code=PUBLICATION_RECOVERY_FAILED",
                PkiFailureReason.PUBLICATION_RECOVERY_FAILED);
    }

    /** Lazy query wrapper retaining the stable store cursor. */
    private static final class FilteringCursor implements PublicationCursor {
        private final PublicationCursor delegate;
        private final PublicationQuery query;

        private FilteringCursor(PublicationCursor delegate, PublicationQuery query) {
            this.delegate = delegate;
            this.query = query;
        }

        @Override
        public Optional<PublicationRecord> next(CancellationSignal cancellation) throws IOException {
            Optional<PublicationRecord> next;
            while ((next = delegate.next(cancellation)).isPresent()) {
                PublicationRecord record = next.orElseThrow();
                boolean targetMatch = query.targetType().isEmpty()
                        || query.targetType().orElseThrow() == record.target().type();
                boolean afterMatch = query.after().isEmpty()
                        || !record.createdAt().isBefore(query.after().orElseThrow());
                boolean beforeMatch = query.before().isEmpty()
                        || !record.createdAt().isAfter(query.before().orElseThrow());
                boolean sourceMatch = query.sourceType().isEmpty()
                        || query.sourceType().orElseThrow() == record.sourceType();
                if (targetMatch && afterMatch && beforeMatch && sourceMatch) {
                    return next;
                }
            }
            return Optional.empty();
        }

        @Override
        public void close() {
            delegate.close();
        }
    }
}
