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

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.List;
import java.util.Objects;

/**
 * Bounded committed-prefix validation and exact-once candidate application.
 */
final class SigningCommittedPrefixReader {

    private static final long NO_APPLIED_FRAMES = 0L;

    private SigningCommittedPrefixReader() {
        // utility class
    }

    /**
     * Reads one prefix and adapts validated groups to frame-at-a-time consumers.
     * @param channel borrowed source channel whose position may change
     * @param descriptor exact lower-exclusive and forced-upper-inclusive generation bounds
     * @param candidateRevision last revision already present in the detached candidate
     * @param publishedMvccRevision greatest authoritative revision currently visible in MVCC
     * @param consumer callback receiving only eligible validated frames or groups
     * @return accepted physical prefix, applied frame count and agreement with the forced MVCC endpoint
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if candidate revision precedes the descriptor start or exceeds published MVCC
     * @throws IOException if bounded framing, integrity, continuity or the callback fails
     */
    /* default */ static Result read(SeekableByteChannel channel,
            CommittedPrefixDescriptor descriptor, long candidateRevision,
            long publishedMvccRevision, FrameConsumer consumer) throws IOException {
        Objects.requireNonNull(consumer, "consumer");
        return read(channel, descriptor, candidateRevision, publishedMvccRevision,
                (frames, group) -> {
                    for (SigningWalFrameCodec.ScannedFrame frame : frames) {
                        consumer.accept(frame);
                    }
                });
    }

    /**
     * Reads validated groups after the descriptor start and applies only revisions
     * absent from the supplied candidate and already visible in MVCC.
     * @param channel borrowed source channel whose position may change
     * @param descriptor exact lower-exclusive and forced-upper-inclusive generation bounds
     * @param candidateRevision last revision already present in the detached candidate
     * @param publishedMvccRevision greatest authoritative revision currently visible in MVCC
     * @param consumer callback receiving only eligible validated frames or groups
     * @return accepted physical prefix, applied frame count and agreement with the forced MVCC endpoint
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if candidate revision precedes the descriptor start or exceeds published MVCC
     * @throws IOException if bounded framing, integrity, continuity or the callback fails
     */
    /* default */ static Result read(SeekableByteChannel channel,
            CommittedPrefixDescriptor descriptor, long candidateRevision,
            long publishedMvccRevision, GroupConsumer consumer) throws IOException {
        Objects.requireNonNull(channel, "channel");
        Objects.requireNonNull(descriptor, "descriptor");
        Objects.requireNonNull(consumer, "consumer");
        if (candidateRevision < descriptor.exclusiveStartRevision()
                || publishedMvccRevision < candidateRevision) {
            throw new IllegalArgumentException("signing committed-prefix revision bounds are invalid");
        }
        long[] applied = { 0L };
        CommittedPrefixDescriptor[] cursor = { new CommittedPrefixDescriptor(
                descriptor.generationId(), descriptor.exclusiveStartOffset(),
                descriptor.exclusiveStartSequence(), descriptor.exclusiveStartRevision(),
                descriptor.exclusiveStartCommitment(), descriptor.exclusiveStartOffset(),
                descriptor.exclusiveStartSequence(), descriptor.exclusiveStartRevision(),
                descriptor.exclusiveStartCommitment()) };
        SigningWalFrameCodec.PrefixScanResult scan =
                SigningWalFrameCodec.scanCommittedPrefix(channel, descriptor,
                        publishedMvccRevision, (frames, commit, acceptedOffset) -> applyEligible(
                                frames, candidateRevision, publishedMvccRevision,
                                commit, acceptedOffset, consumer, applied, cursor));
        CommittedPrefixDescriptor accepted = new CommittedPrefixDescriptor(
                descriptor.generationId(), descriptor.exclusiveStartOffset(),
                descriptor.exclusiveStartSequence(), descriptor.exclusiveStartRevision(),
                descriptor.exclusiveStartCommitment(), scan.acceptedOffset(),
                scan.lastSequence(), scan.committedRevision(), scan.rollingCommitment());
        boolean endpointsEqual = scan.forcedEndReached()
                && scan.acceptedOffset() == descriptor.inclusiveForcedEndOffset()
                && scan.lastSequence() == descriptor.inclusiveForcedEndSequence()
                && scan.committedRevision() == publishedMvccRevision;
        return new Result(accepted, applied[0], endpointsEqual);
    }

    private static void applyEligible(List<SigningWalFrameCodec.ScannedFrame> frames,
            long candidateRevision, long publishedMvccRevision,
            SigningWalFrameCodec.BatchCommit commit, long acceptedOffset,
            GroupConsumer consumer, long[] applied,
            CommittedPrefixDescriptor... cursor) throws IOException {
        int firstEligible = frames.size();
        for (int index = 0; index < frames.size(); index++) {
            if (frames.get(index).revision() > candidateRevision) {
                firstEligible = index;
                break;
            }
        }
        for (SigningWalFrameCodec.ScannedFrame frame : frames) {
            if (frame.revision() > candidateRevision
                    && frame.revision() <= publishedMvccRevision) {
                applied[0] = Math.incrementExact(applied[0]);
            }
        }
        CommittedPrefixDescriptor prior = cursor[0];
        SigningWalFrameCodec.ScannedFrame last = frames.getLast();
        CommittedPrefixDescriptor group = new CommittedPrefixDescriptor(
                prior.generationId(), prior.inclusiveForcedEndOffset(),
                prior.inclusiveForcedEndSequence(), prior.inclusiveForcedEndRevision(),
                prior.inclusiveForcedEndCommitment(), acceptedOffset,
                last.frame().sequence(), last.revision(),
                commit.resultingCommitment());
        consumer.accept(frames.subList(firstEligible, frames.size()), group);
        cursor[0] = group;
    }

    /**
     * Receives one validated frame that is eligible for candidate application.
     */
    /* default */ @FunctionalInterface
    interface GroupConsumer {
        /**
         * Applies one eligible committed group and advances to its accepted endpoint.
         *
         * @param frames validated contiguous frames absent from the candidate and already visible in MVCC
         * @param acceptedGroup exact descriptor ending after this eligible committed group
         * @throws IOException if candidate application fails
         */
        void accept(List<SigningWalFrameCodec.ScannedFrame> frames,
                CommittedPrefixDescriptor acceptedGroup) throws IOException;
    }

    /**
     * Receives one validated frame eligible for application.
     */
    /* default */ @FunctionalInterface
    interface FrameConsumer {
        /**
         * Applies one eligible frame.
         *
         * @param frame validated physical frame absent from the candidate and already visible in MVCC
         * @throws IOException if candidate application fails
         */
        void accept(SigningWalFrameCodec.ScannedFrame frame) throws IOException;
    }

    /* default */ /**
     * Applied committed-prefix evidence and agreement with the forced WAL endpoint.
     *
     * @param acceptedPrefix exact committed prefix accepted by the reader
     * @param appliedFrames number of frames applied from that prefix
     * @param forcedAndProjectedEndpointsEqual whether forced and projected end coordinates agree
     */
    @SuppressWarnings("PMD.LongVariable")
    record Result(CommittedPrefixDescriptor acceptedPrefix,
            long appliedFrames, boolean forcedAndProjectedEndpointsEqual) {
        /**
         * Creates the applied committed-prefix evidence and agreement with the forced WAL endpoint.
         *
         * @param acceptedPrefix exact committed prefix accepted by the reader
         * @param appliedFrames number of frames applied from that prefix
         * @param forcedAndProjectedEndpointsEqual whether forced and projected end coordinates agree
         * @throws NullPointerException if {@code acceptedPrefix} is null
         * @throws IllegalArgumentException if {@code (appliedFrames < NO_APPLIED_FRAMES)}
         */
        Result {
            Objects.requireNonNull(acceptedPrefix, "acceptedPrefix");
            if (appliedFrames < NO_APPLIED_FRAMES) {
                throw new IllegalArgumentException(
                        "signing committed-prefix applied count is invalid");
            }
        }
    }
}
