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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.function.Consumer;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.pki.impl.core.CrlScope;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataCursor;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataSnapshot;
import zeroecho.pki.spi.store.MetadataTransaction;
import zeroecho.pki.spi.store.TransactionalMetadataStore;

/**
 * Permanent create-only scope claims in the existing metadata authority. Uses
 * at most two create attempts: a competing owner claim can eliminate one of
 * the two missing records; a subsequent serial conflict has a final owner.
 * No application lock spans WAL I/O, and there is no cache or new ledger.
 */
final class CrlScopeReservationStore { // NOPMD - CyclomaticComplexity totals independent dispatch/codec branches; method-level checks remain enabled.
    private static final int MAXIMUM_RESERVE_ATTEMPTS = 8;
    private static final ThreadLocal<CounterCommitFault> COUNTER_COMMIT_FAULT = new ThreadLocal<>();
    private final TransactionalMetadataStore metadata;
    private final Consumer<MetadataCommitResult> outcome;
    private final BigInteger initialCrlNumber;
    /** Visits an owner participating in CRL counter reservation. */
    /* default */ @FunctionalInterface interface OwnerVisitor {
        /** Processes one retained scope owner.
         * @param owner retained scope owner
         * @throws IOException if processing fails
         */
        void accept(CrlScopeOwner owner) throws IOException;
    }

    /* default */ CrlScopeReservationStore(TransactionalMetadataStore metadata, BigInteger initialCrlNumber,
            Consumer<MetadataCommitResult> outcome) {
        this.metadata = Objects.requireNonNull(metadata, "metadata");
        this.outcome = Objects.requireNonNull(outcome, "outcome");
        this.initialCrlNumber = Objects.requireNonNull(initialCrlNumber, "initialCrlNumber");
        if (initialCrlNumber.signum() < 0 || initialCrlNumber.bitLength() > 159) {
            throw new IllegalArgumentException("Initial CRL number is outside its issued range");
        }
    }

    /**
     * Streams permanent authority and validates owner/counter pairs without
     * reconstruction. Adds O(S) point reads for S scopes and retains only one
     * bounded record at a time, independent of the scope population.
     */
    /* default */ void validateAuthority(ReservationVisitor visitor) throws IOException {
        validateAuthority(owner -> { }, visitor);
    }

    /* default */ // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
                  @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
                  void validateAuthority(OwnerVisitor owners, ReservationVisitor visitor) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(
                    "io.zeroecho.pki.crl-scope-owner"), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        CrlScopeOwner owner = CrlScopeMetadataCodec.decodeOwner(read(record));
                        if (!record.key().equals(CrlScopeMetadataCodec.key(owner))) {
                            throw new IOException("CRL scope ownership metadata differs from its key");
                        }
                        readCounter(snapshot, owner.scope())
                                .orElseThrow(() -> new IOException("CRL scope counter is missing"));
                        owners.accept(owner);
                    }
                }
            }
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(
                    "io.zeroecho.pki.crl-scope-counter"), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        CrlScopeCounter counter = decodeCounter(record);
                        readOwner(snapshot, new MetadataKey("io.zeroecho.pki.crl-scope-owner", counter.scopeDigest()))
                                .orElseThrow(() -> new IOException("CRL scope counter owner is missing"));
                    }
                }
            }
            try (MetadataCursor cursor = snapshot.scan(MetadataSnapshot.KeyRange.all(
                    "io.zeroecho.pki.scope-serial"), CancellationSignal.NONE)) {
                Optional<MetadataSnapshot.Record> next;
                while ((next = cursor.next(CancellationSignal.NONE)).isPresent()) {
                    try (MetadataSnapshot.Record record = next.orElseThrow()) {
                        ScopeSerialReservation reservation = CrlScopeMetadataCodec.decodeReservation(read(record));
                        if (!record.key().equals(CrlScopeMetadataCodec.key(reservation))) {
                            throw new IOException("CRL scope serial metadata differs from its key");
                        }
                        CrlScopeOwner owner = readOwner(snapshot, reservation.scope())
                                .orElseThrow(() -> new IOException("CRL scope serial owner is missing"));
                        visitor.accept(owner, reservation);
                    }
                }
            }
        }
    }

    /** Checked visitor over a scope owner and its serial reservation. */
    /* default */
    @FunctionalInterface
    interface ReservationVisitor {
        /** Consumes one owner and reservation pair. */
        void accept(CrlScopeOwner owner, ScopeSerialReservation reservation) throws IOException;
    }

    /* default */ void claim(CrlScopeOwner owner) throws IOException { claim(owner, null); }

    /** Adds only missing immutable claims to the caller's atomic acceptance transaction. */
    /* default */ void stageAcceptance(MetadataTransaction transaction, SignAcceptanceCrlScope claims) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            stageAcceptance(snapshot, transaction, claims);
        }
    }

    /** Stages in the caller's pinned view and transaction, without committing. */
    /* default */ void stageAcceptance(MetadataSnapshot snapshot, MetadataTransaction transaction, SignAcceptanceCrlScope claims) throws IOException {
            CrlScopeOwner previous = null;
            for (CrlScopeOwner owner : claims.owners()) {
                if (previous != null && previous.scope().equals(owner.scope())) {
                    if (!previous.equals(owner)) { throw new ConflictException(); }
                    continue;
                }
                if (requireOwner(snapshot, owner)) {
                    createOwnerAndCounter(transaction, owner);
                }
                previous = owner;
            }
            ScopeSerialReservation reservation = claims.reservation();
            if (requireReservation(snapshot, reservation)) {
                create(transaction, CrlScopeMetadataCodec.key(reservation), CrlScopeMetadataCodec.encode(reservation));
            }
    }

    /** Stages an immutable owner/counter and optional serial claim without committing. */
    /* default */ void stageClaim(MetadataSnapshot snapshot, MetadataTransaction transaction, CrlScopeOwner owner,
            ScopeSerialReservation reservation) throws IOException {
        if (reservation != null && !owner.scope().equals(reservation.scope())) {
            throw new IllegalArgumentException("Reservation scope differs from its authority claim");
        }
        if (requireOwner(snapshot, owner)) { createOwnerAndCounter(transaction, owner); }
        if (reservation != null && requireReservation(snapshot, reservation)) {
            create(transaction, CrlScopeMetadataCodec.key(reservation), CrlScopeMetadataCodec.encode(reservation));
        }
    }

    /** Publication cannot introduce an accepted signing operation's reservation. */
    /* default */ void verify(CrlScopeOwner owner, ScopeSerialReservation reservation) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            if (requireOwner(snapshot, owner) || requireReservation(snapshot, reservation)) {
                throw new IllegalStateException("Signing acceptance scope reservation is missing");
            }
        }
    }

    /** Signals a conflicting immutable scope or serial claim. */
    /* default */ static final class ConflictException extends IllegalStateException {
        private static final long serialVersionUID = 1L;
        /* default */ ConflictException() { super("CRL scope or serial belongs to another authority or issuance"); }
    }

    /* default */ void claim(CrlScopeOwner owner, ScopeSerialReservation reservation) throws IOException {
        Objects.requireNonNull(owner, "owner");
        if (reservation != null && !owner.scope().equals(reservation.scope())) {
            throw new IllegalArgumentException("Reservation scope differs from its authority claim");
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            boolean ownerMissing;
            boolean serialMissing;
            try (MetadataSnapshot snapshot = metadata.snapshot()) {
                ownerMissing = requireOwner(snapshot, owner);
                serialMissing = reservation != null && requireReservation(snapshot, reservation);
            }
            if (!ownerMissing && !serialMissing) {
                return;
            }
            try (MetadataTransaction transaction = metadata.beginTransaction()) {
                if (ownerMissing) {
                    createOwnerAndCounter(transaction, owner);
                }
                if (serialMissing) {
                    create(transaction, CrlScopeMetadataCodec.key(reservation), CrlScopeMetadataCodec.encode(reservation));
                }
                MetadataCommitResult result = transaction.commit();
                outcome.accept(result);
                if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                    return;
                }
                if (result.outcome() != MetadataCommitResult.Outcome.NOT_COMMITTED
                        || result.failureCategory().orElse(null) != MetadataCommitResult.FailureCategory.CONFLICT) {
                    throw new IOException("CRL scope reservation was not durably committed");
                }
            }
        }
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            if (requireOwner(snapshot, owner) || reservation != null && requireReservation(snapshot, reservation)) {
                throw new IOException("CRL scope reservation did not converge after a create conflict");
            }
        }
    }

    /* default */ Optional<CrlScopeOwner> findOwner(CrlScope scope) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            return readOwner(snapshot, scope);
        }
    }

    /* default */ Optional<CrlScopeOwner> findOwner(MetadataSnapshot snapshot, CrlScope scope) throws IOException { return readOwner(snapshot, scope); }

    /* default */ Optional<ScopeSerialReservation> findReservation(MetadataSnapshot snapshot, CrlScope scope, BigInteger serial) throws IOException {
        return readReservation(snapshot, scope, serial);
    }

    /* default */ Optional<ScopeSerialReservation> findReservation(CrlScope scope, BigInteger serial) throws IOException {
        try (MetadataSnapshot snapshot = metadata.snapshot()) {
            return readReservation(snapshot, scope, serial);
        }
    }

    private static boolean requireOwner(MetadataSnapshot snapshot, CrlScopeOwner expected) throws IOException {
        Optional<CrlScopeOwner> current = readOwner(snapshot, expected.scope());
        if (current.isPresent() && !current.orElseThrow().equals(expected)) {
            throw new ConflictException();
        }
        Optional<CounterValue> counter = readCounter(snapshot, expected.scope());
        if (current.isPresent() != counter.isPresent()) {
            throw new IOException("CRL scope owner and counter pair is incomplete");
        }
        return current.isEmpty();
    }

    private void createOwnerAndCounter(MetadataTransaction transaction, CrlScopeOwner owner) throws IOException {
        CrlScopeCounter counter = new CrlScopeCounter(owner.scope().digest(), initialCrlNumber);
        create(transaction, CrlScopeMetadataCodec.key(owner), CrlScopeMetadataCodec.encode(owner));
        create(transaction, CrlScopeMetadataCodec.key(counter), CrlScopeMetadataCodec.encode(counter));
    }

    /** Reserves with one counter-row CAS; owner authority is immutable. */
    /* default */ // Each iteration requires its own immutable value or failure object; sharing would conflate distinct records or attempts.
                  @SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops" })
                  BigInteger reserve(CrlScopeOwner owner) throws IOException {
        Objects.requireNonNull(owner, "owner");
        for (int attempt = 0; attempt < MAXIMUM_RESERVE_ATTEMPTS; attempt++) {
            CounterValue current;
            try (MetadataSnapshot snapshot = metadata.snapshot()) {
                if (requireOwner(snapshot, owner)) {
                    throw new IllegalStateException("CRL scope owner is missing");
                }
                current = readCounter(snapshot, owner.scope())
                        .orElseThrow(() -> new IOException("CRL scope counter is missing"));
            }
            BigInteger number = current.counter().nextNumber();
            if (number.equals(CrlScopeCounter.EXHAUSTED)) {
                throw new IllegalStateException("CRL number sequence is exhausted");
            }
            CrlScopeCounter replacement = new CrlScopeCounter(owner.scope().digest(), number.add(BigInteger.ONE));
            try (MetadataTransaction transaction = metadata.beginTransaction();
                    RepeatableContent content = new ImmutableByteContent(CrlScopeMetadataCodec.encode(replacement))) {
                transaction.replace(CrlScopeMetadataCodec.key(replacement), current.revision(), content,
                        CancellationSignal.NONE);
                MetadataCommitResult result = commitCounter(transaction);
                outcome.accept(result);
                if (result.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
                    return number;
                }
                if (result.outcome() == MetadataCommitResult.Outcome.UNKNOWN
                        || result.failureCategory().orElse(null) == MetadataCommitResult.FailureCategory.STORAGE_FAILURE) {
                    throw new IOException("CRL number reservation durability is unconfirmed");
                }
                if (result.failureCategory().orElse(null) != MetadataCommitResult.FailureCategory.CONFLICT) {
                    throw new IllegalStateException("CRL number reservation was not committed");
                }
            }
        }
        throw new IllegalStateException("CRL number reservation exceeded its contention bound");
    }

    private static Optional<CounterValue> readCounter(MetadataSnapshot snapshot, CrlScope scope) throws IOException {
        MetadataKey key = CrlScopeMetadataCodec.counterKey(scope);
        Optional<MetadataSnapshot.Record> found = snapshot.get(key);
        if (found.isEmpty()) { return Optional.empty(); }
        try (MetadataSnapshot.Record record = found.orElseThrow()) {
            return Optional.of(new CounterValue(decodeCounter(record), record.recordRevision()));
        }
    }

    private static CrlScopeCounter decodeCounter(MetadataSnapshot.Record record) throws IOException {
        if (record.length().orElseThrow() > CrlScopeMetadataCodec.MAXIMUM_COUNTER_ENCODED_BYTES) {
            throw new IOException("CRL scope counter exceeds its finite size bound");
        }
        return CrlScopeMetadataCodec.decodeCounter(record.key(), read(record));
    }

    private record CounterValue(CrlScopeCounter counter, long revision) { }

    // Calling-thread fault seam follows the store's existing commit-prefix tests.
    /** Injection points for uncertain counter commit outcomes. */
    /* default */ enum CounterCommitFault { BEFORE_COMMIT_FAILURE, BEFORE_COMMIT_AS_UNKNOWN, AFTER_COMMIT_AS_UNKNOWN }

    /* default */ static void installCounterCommitFault(CounterCommitFault fault) {
        COUNTER_COMMIT_FAULT.set(Objects.requireNonNull(fault, "fault"));
    }

    /* default */ static void clearCounterCommitFault() { COUNTER_COMMIT_FAULT.remove(); }

    private static MetadataCommitResult commitCounter(MetadataTransaction transaction) throws IOException {
        CounterCommitFault fault = COUNTER_COMMIT_FAULT.get();
        if (fault == CounterCommitFault.BEFORE_COMMIT_FAILURE) {
            throw new IllegalStateException("Injected definite CRL number reservation failure");
        }
        if (fault == CounterCommitFault.BEFORE_COMMIT_AS_UNKNOWN) {
            return new MetadataCommitResult(transaction.id(), MetadataCommitResult.Outcome.UNKNOWN,
                    OptionalLong.empty(), Optional.empty());
        }
        MetadataCommitResult result = transaction.commit();
        if (fault == CounterCommitFault.AFTER_COMMIT_AS_UNKNOWN
                && result.outcome() == MetadataCommitResult.Outcome.COMMITTED) {
            return new MetadataCommitResult(result.transactionId(), MetadataCommitResult.Outcome.UNKNOWN,
                    OptionalLong.empty(), Optional.empty());
        }
        return result;
    }

    private static boolean requireReservation(MetadataSnapshot snapshot, ScopeSerialReservation expected)
            throws IOException {
        Optional<ScopeSerialReservation> current = readReservation(snapshot, expected.scope(), expected.serial());
        if (current.isPresent() && !current.orElseThrow().equals(expected)) {
            throw new ConflictException();
        }
        return current.isEmpty();
    }

    private static Optional<CrlScopeOwner> readOwner(MetadataSnapshot snapshot, CrlScope scope) throws IOException {
        Optional<CrlScopeOwner> owner = readOwner(snapshot, CrlScopeMetadataCodec.ownerKey(scope));
        if (owner.isPresent() && !scope.equals(owner.orElseThrow().scope())) {
            throw new IOException("CRL scope ownership metadata differs from its scope");
        }
        return owner;
    }

    private static Optional<CrlScopeOwner> readOwner(MetadataSnapshot snapshot, MetadataKey key) throws IOException {
        Optional<byte[]> encoded = read(snapshot, key);
        if (encoded.isEmpty()) { return Optional.empty(); }
        CrlScopeOwner value = CrlScopeMetadataCodec.decodeOwner(encoded.orElseThrow());
        if (!key.equals(CrlScopeMetadataCodec.key(value))) {
            throw new IOException("CRL scope ownership metadata differs from its key");
        }
        return Optional.of(value);
    }

    private static Optional<ScopeSerialReservation> readReservation(MetadataSnapshot snapshot,
            CrlScope scope, BigInteger serial) throws IOException {
        MetadataKey key = CrlScopeMetadataCodec.reservationKey(scope, serial);
        Optional<byte[]> encoded = read(snapshot, key);
        if (encoded.isEmpty()) { return Optional.empty(); }
        ScopeSerialReservation value = CrlScopeMetadataCodec.decodeReservation(encoded.orElseThrow());
        if (!scope.equals(value.scope()) || !key.equals(CrlScopeMetadataCodec.key(value))) {
            throw new IOException("CRL scope serial metadata differs from its key");
        }
        return Optional.of(value);
    }

    private static Optional<byte[]> read(MetadataSnapshot snapshot, MetadataKey key) throws IOException {
        Optional<MetadataSnapshot.Record> found = snapshot.get(key);
        if (found.isEmpty()) { return Optional.empty(); }
        try (MetadataSnapshot.Record record = found.orElseThrow()) {
            return Optional.of(read(record));
        }
    }

    private static byte[] read(MetadataSnapshot.Record record) throws IOException {
        try (InputStream input = record.openStream()) {
            long length = record.length().orElseThrow();
            if (length <= 0 || length > CrlScopeMetadataCodec.MAXIMUM_ENCODED_BYTES) {
                throw new IOException("Invalid CRL scope metadata size");
            }
            byte[] encoded = input.readNBytes(Math.toIntExact(length));
            if (encoded.length != length || input.read() != -1) {
                throw new IOException("Invalid CRL scope metadata length");
            }
            return encoded;
        }
    }

    private static void create(MetadataTransaction transaction, MetadataKey key, byte[] encoded) throws IOException {
        try (RepeatableContent content = new RepeatableContent() {
            @Override public InputStream openStream() { return new ByteArrayInputStream(encoded); }
            @Override public OptionalLong length() { return OptionalLong.of(encoded.length); }
            @Override public String contentId() { return "crl-scope-metadata"; }
            @Override public void close() { /* Byte-array content owns no external resources. */ }
        }) {
            transaction.create(key, content, CancellationSignal.NONE);
        }
    }
}
