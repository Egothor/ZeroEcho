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

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import zeroecho.pki.spi.store.MetadataKey;

/**
 * Detached MVCC relocation ownership and its short-lived prepared swap.
 *
 * <p>The token lock is outermost, followed by the live index, this candidate
 * lifecycle lock, and the detached index. Lifecycle locks protect only scalar
 * ownership transitions. WAL I/O, frame decoding callbacks, and owner cleanup
 * run without either lifecycle lock.</p>
 */
final class SigningMvccRelocationCandidate implements AutoCloseable {
    private final SigningMvccIndex owner;
    private final SigningMvccIndex detached;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final long checkpointEndOffset;
    private CommittedPrefixDescriptor acceptedPrefix;
    private State state = State.AVAILABLE;
    private PreparedRootSwap preparedSwap;

    /* default */ SigningMvccRelocationCandidate(SigningMvccIndex owner,
            SigningMvccIndex detached, CommittedPrefixDescriptor acceptedPrefix,
            long checkpointEndOffset) {
        this.owner = Objects.requireNonNull(owner, "owner");
        this.detached = Objects.requireNonNull(detached, "detached");
        this.acceptedPrefix = Objects.requireNonNull(acceptedPrefix, "acceptedPrefix");
        if (detached.currentRevision() != acceptedPrefix.inclusiveForcedEndRevision()
                || detached.lastSequence() != acceptedPrefix.inclusiveForcedEndSequence()) {
            throw new IllegalArgumentException(
                    "signing relocation accepted boundary is inconsistent");
        }
        this.checkpointEndOffset = checkpointEndOffset;
    }

    /** Applies one newly accepted committed prefix only to the detached index. */
    /* default */ SigningCommittedPrefixReader.Result catchUp(
            SeekableByteChannel channel, CommittedPrefixDescriptor descriptor,
            long publishedMvccRevision, FrameMutationDecoder decoder) throws IOException {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(descriptor, "descriptor");
        Objects.requireNonNull(decoder, "decoder");
        beginUpdate(descriptor);
        boolean completed = false;
        try {
            SigningCommittedPrefixReader.Result result = SigningCommittedPrefixReader.read(
                    channel, descriptor, detached.currentRevision(), publishedMvccRevision,
                    (frames, acceptedGroup) -> applyGroup(
                            descriptor.generationId(), frames, acceptedGroup, decoder));
            CommittedPrefixDescriptor accepted = result.acceptedPrefix();
            if (detached.currentRevision() != accepted.inclusiveForcedEndRevision()
                    || detached.lastSequence() != accepted.inclusiveForcedEndSequence()) {
                throw new IllegalStateException(
                        "signing relocation candidate catch-up is inconsistent");
            }
            completeUpdate();
            completed = true;
            return result;
        } finally {
            if (!completed) {
                abortUpdate();
            }
        }
    }

    /** Returns one candidate-only current record for deterministic verification. */
    /* default */ Optional<SigningMvccIndex.SnapshotRecord> lookup(MetadataKey key) {
        lifecycleLock.lock();
        try {
            requireUsable();
            return detached.lookup(key);
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ long revision() {
        lifecycleLock.lock();
        try {
            requireUsable();
            return detached.currentRevision();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ long lastSequence() {
        lifecycleLock.lock();
        try {
            requireUsable();
            return detached.lastSequence();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ byte[] commitment() {
        lifecycleLock.lock();
        try {
            requireUsable();
            return acceptedPrefix.inclusiveForcedEndCommitment();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ long checkpointEndOffset() {
        return checkpointEndOffset;
    }

    /** Returns the immutable authoritative accepted-prefix cursor. */
    /* default */ CommittedPrefixDescriptor acceptedPrefix() {
        lifecycleLock.lock();
        try {
            requireUsable();
            return acceptedPrefix;
        } finally {
            lifecycleLock.unlock();
        }
    }

    // Owner instances are capability identities; value equality would permit a
    // different live index to claim this candidate.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    /* default */ boolean ownedBy(SigningMvccIndex expectedOwner) {
        return owner == expectedOwner;
    }

    /* default */ PreparedRootSwap prepare(long expectedRevision,
            long expectedSequence, byte[] expectedCommitment) {
        byte[] checked = checkedCommitment(expectedCommitment);
        lifecycleLock.lock();
        try {
            requireAvailable();
            requireEndpoint(expectedRevision, expectedSequence, checked);
            PreparedRootSwap prepared = new PreparedRootSwap(owner, this,
                    expectedRevision, expectedSequence, checked);
            try (SigningMvccIndex.RelocationRootState rootState =
                    detached.detachRelocationRoot()) {
                prepared.attachRoot(rootState);
                rootState.prepareTransfer();
                state = State.PREPARED;
                preparedSwap = prepared;
                return prepared;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    // The prepared token is a unique capability, so only the exact instance may
    // publish this candidate.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    /* default */ void requirePrepared(PreparedRootSwap expected,
            long expectedRevision, long expectedSequence) {
        lifecycleLock.lock();
        try {
            if (state != State.PREPARED || preparedSwap != expected) {
                throw new IllegalStateException("signing relocation swap is not active");
            }
            if (expected.relocationRoot().revision() != expectedRevision
                    || expected.relocationRoot().lastSequence() != expectedSequence
                    || !acceptedPrefix.matchesInclusiveForcedEndCommitment(
                            expected.expectedCommitment)) {
                throw new IllegalStateException(
                        "signing relocation swap endpoint is inconsistent");
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    // Publication consumes the same unique prepared capability that owns the
    // detached root; value equality is intentionally invalid.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    /* default */ void transferred(PreparedRootSwap expected) {
        lifecycleLock.lock();
        try {
            if (state != State.PREPARED || preparedSwap != expected) {
                throw new IllegalStateException("signing relocation swap is not active");
            }
            state = State.TRANSFERRED;
            preparedSwap = null;
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void beginUpdate(CommittedPrefixDescriptor descriptor) {
        lifecycleLock.lock();
        try {
            requireAvailable();
            requireAnchored(descriptor);
            state = State.UPDATING;
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void completeUpdate() {
        lifecycleLock.lock();
        try {
            if (state != State.UPDATING) {
                throw new IllegalStateException(
                        "signing relocation candidate update ownership is inconsistent");
            }
            state = State.AVAILABLE;
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void abortUpdate() {
        lifecycleLock.lock();
        try {
            if (state == State.UPDATING) {
                state = State.AVAILABLE;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    // Every validated frame necessarily produces a distinct immutable pointer
    // and committed-frame result; WAL group cardinality is bounded to at most 32.
    @SuppressWarnings("PMD.AvoidInstantiatingObjectsInLoops")
    private void applyGroup(long generationId,
            List<SigningWalFrameCodec.ScannedFrame> frames,
            CommittedPrefixDescriptor acceptedGroup,
            FrameMutationDecoder decoder) throws IOException {
        List<SigningMvccIndex.CommittedFrame> committedFrames =
                new ArrayList<>(frames.size());
        for (SigningWalFrameCodec.ScannedFrame frame : frames) {
            SigningWalFrameCodec.Frame committed = frame.frame();
            SigningMvccIndex.RecordPointer pointer = new SigningMvccIndex.RecordPointer(
                    generationId, frame.offset(), frame.encodedLength(), committed.sequence(),
                    frame.revision(), committed.recordType());
            List<SigningMvccIndex.Mutation> mutations = List.copyOf(Objects.requireNonNull(
                    decoder.decode(frame, pointer), "mutations"));
            committedFrames.add(new SigningMvccIndex.CommittedFrame(
                    frame.revision(), committed.sequence(), mutations));
        }
        if (!committedFrames.isEmpty()) {
            detached.applyDetachedGroup(committedFrames);
        }
        advanceAccepted(acceptedGroup);
    }

    /* default */ long appliedGroups() {
        lifecycleLock.lock();
        try {
            requireUsable();
            return detached.detachedGroupApplications();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ long generationReferenceCopies() {
        lifecycleLock.lock();
        try {
            requireUsable();
            return detached.detachedReferenceMapCopies();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /* default */ long steadyReservedBytes() {
        lifecycleLock.lock();
        try {
            requireUsable();
            return detached.steadyReservedBytes();
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void advanceAccepted(CommittedPrefixDescriptor group) {
        lifecycleLock.lock();
        try {
            if (state != State.UPDATING) {
                throw new IllegalStateException(
                        "signing relocation candidate update ownership is inconsistent");
            }
            requireAnchored(group);
            acceptedPrefix = new CommittedPrefixDescriptor(acceptedPrefix.generationId(),
                    acceptedPrefix.exclusiveStartOffset(),
                    acceptedPrefix.exclusiveStartSequence(),
                    acceptedPrefix.exclusiveStartRevision(),
                    acceptedPrefix.exclusiveStartCommitment(),
                    group.inclusiveForcedEndOffset(), group.inclusiveForcedEndSequence(),
                    group.inclusiveForcedEndRevision(),
                    group.inclusiveForcedEndCommitment());
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void requireAnchored(CommittedPrefixDescriptor next) {
        if (next.generationId() != acceptedPrefix.generationId()
                || next.exclusiveStartOffset() != acceptedPrefix.inclusiveForcedEndOffset()
                || next.exclusiveStartSequence() != acceptedPrefix.inclusiveForcedEndSequence()
                || next.exclusiveStartRevision() != acceptedPrefix.inclusiveForcedEndRevision()
                || !MessageDigest.isEqual(next.exclusiveStartCommitment(),
                        acceptedPrefix.inclusiveForcedEndCommitment())) {
            throw new IllegalArgumentException(
                    "signing relocation committed prefix is not anchored");
        }
    }

    private void requireEndpoint(long expectedRevision, long expectedSequence,
            byte[] expectedCommitment) {
        if (detached.currentRevision() != expectedRevision
                || detached.lastSequence() != expectedSequence
                || !MessageDigest.isEqual(acceptedPrefix.inclusiveForcedEndCommitment(),
                        expectedCommitment)) {
            throw new IllegalStateException("signing relocation swap endpoint is inconsistent");
        }
    }

    private void requireAvailable() {
        if (state != State.AVAILABLE) {
            throw new IllegalStateException("signing relocation candidate is not available");
        }
    }

    private void requireUsable() {
        if (state == State.CLOSED || state == State.TRANSFERRED) {
            throw new IllegalStateException("signing relocation candidate is not available");
        }
    }

    @Override
    public void close() {
        lifecycleLock.lock();
        try {
            if (state == State.CLOSED || state == State.TRANSFERRED) {
                return;
            }
            if (state != State.AVAILABLE) {
                throw new IllegalStateException("signing relocation candidate is in use");
            }
            state = State.CLOSED;
        } finally {
            lifecycleLock.unlock();
        }
        detached.close();
    }

    private static byte[] checkedCommitment(byte[] value) {
        Objects.requireNonNull(value, "commitment");
        if (value.length != SigningFormatSupport.SHA_256_BYTES) {
            throw new IllegalArgumentException("signing relocation commitment is invalid");
        }
        return value.clone();
    }

    /** Decodes one validated committed frame into its bounded MVCC mutations. */
    /* default */ @FunctionalInterface
    interface FrameMutationDecoder {
        /** Returns the semantic mutations represented by one committed frame. */
        List<SigningMvccIndex.Mutation> decode(SigningWalFrameCodec.ScannedFrame frame,
                SigningMvccIndex.RecordPointer pointer) throws IOException;
    }

    /** Short-lived rollback token owning one detached root until publication. */
    /* default */ static final class PreparedRootSwap implements AutoCloseable {
        private final SigningMvccIndex owner;
        private final SigningMvccRelocationCandidate candidate;
        private SigningMvccIndex.RelocationRootState rootState;
        private SigningIndexCapacityBudget.CutoverPermit capacityPermit;
        private final long expectedRevision;
        private final long expectedSequence;
        private final byte[] expectedCommitment;
        private final ReentrantLock lifecycleLock = new ReentrantLock();
        private Map<Long, Integer> previousReferences;
        private long previousReservedBytes;
        private boolean releasePreviousReservation;
        private boolean active = true;
        private boolean published;

        private PreparedRootSwap(SigningMvccIndex owner,
                SigningMvccRelocationCandidate candidate,
                long expectedRevision, long expectedSequence, byte[] expectedCommitment) {
            this.owner = owner;
            this.candidate = candidate;
            this.expectedRevision = expectedRevision;
            this.expectedSequence = expectedSequence;
            this.expectedCommitment = expectedCommitment;
        }

        /** Publishes the already prepared candidate root without allocation or I/O. */
        /* default */ void publish() {
            lifecycleLock.lock();
            try {
                if (!active || published) {
                    throw new IllegalStateException("signing relocation swap is not active");
                }
                owner.publishRelocationSwap(this);
            } finally {
                lifecycleLock.unlock();
            }
        }

        /* default */ SigningMvccIndex.RelocationRootState relocationRoot() {
            return rootState;
        }

        private void attachRoot(SigningMvccIndex.RelocationRootState value) {
            rootState = Objects.requireNonNull(value, "rootState");
        }

        /* default */ void attachCapacityPermit(
                SigningIndexCapacityBudget.CutoverPermit value) {
            capacityPermit = Objects.requireNonNull(value, "capacityPermit");
        }

        /* default */ SigningIndexCapacityBudget.CutoverPermit capacityPermit() {
            if (capacityPermit == null) {
                throw new IllegalStateException("signing relocation capacity permit is absent");
            }
            return capacityPermit;
        }

        /* default */ SigningMvccRelocationCandidate candidate() {
            return candidate;
        }

        /* default */ long expectedRevision() {
            return expectedRevision;
        }

        /* default */ long expectedSequence() {
            return expectedSequence;
        }

        /* default */ boolean active() {
            return active;
        }

        /* default */ void published(Map<Long, Integer> displacedReferences,
                long displacedReservedBytes, boolean releaseReservation) {
            previousReferences = displacedReferences;
            previousReservedBytes = displacedReservedBytes;
            releasePreviousReservation = releaseReservation;
            published = true;
        }

        @Override
        // The permit is acquired before manifest I/O and therefore cannot be
        // represented by a lexical try-with-resources scope in this close path.
        @SuppressWarnings("PMD.UseTryWithResources")
        public void close() {
            Map<Long, Integer> references = null;
            long reservedBytes = 0L;
            boolean releaseReservation = false;
            boolean rollback = false;
            lifecycleLock.lock();
            try {
                if (!active) {
                    return;
                }
                active = false;
                if (published) {
                    references = previousReferences;
                    reservedBytes = previousReservedBytes;
                    releaseReservation = releasePreviousReservation;
                    previousReferences = null;
                } else {
                    rollback = true;
                }
            } finally {
                lifecycleLock.unlock();
            }
            if (rollback) {
                try {
                    candidate.rollback(this);
                    rootState.rollbackPrepared();
                } finally {
                    capacityPermit().close();
                }
                return;
            }
            try {
                owner.releaseDisplacedRoot(references, reservedBytes, releaseReservation);
            } finally {
                capacityPermit().close();
            }
        }
    }

    // Rollback is authorized only by the exact token that owns the prepared
    // candidate root.
    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    private void rollback(PreparedRootSwap expected) {
        lifecycleLock.lock();
        try {
            if (state == State.PREPARED && preparedSwap == expected) {
                preparedSwap = null;
                state = State.CLOSED;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /** Candidate lifecycle states owned exclusively by {@link #lifecycleLock}. */
    private enum State {
        AVAILABLE,
        UPDATING,
        PREPARED,
        TRANSFERRED,
        CLOSED
    }
}
