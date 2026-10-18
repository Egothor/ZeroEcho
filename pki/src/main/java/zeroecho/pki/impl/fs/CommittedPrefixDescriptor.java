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

import java.security.MessageDigest;
import java.util.Objects;

/** Immutable lower-exclusive and forced-upper-inclusive active-WAL prefix bounds. */
record CommittedPrefixDescriptor(long generationId,
        long exclusiveStartOffset, long exclusiveStartSequence,
        long exclusiveStartRevision, byte[] exclusiveStartCommitment,
        long inclusiveForcedEndOffset, long inclusiveForcedEndSequence,
        long inclusiveForcedEndRevision, byte[] inclusiveForcedEndCommitment) {

    CommittedPrefixDescriptor {
        requireCommitment(exclusiveStartCommitment);
        requireCommitment(inclusiveForcedEndCommitment);
        if (generationId < 0L
                || exclusiveStartOffset < SigningWalContainerCodec.HEADER_BYTES
                || inclusiveForcedEndOffset < exclusiveStartOffset
                || exclusiveStartSequence < -1L
                || inclusiveForcedEndSequence < exclusiveStartSequence
                || exclusiveStartRevision < 0L
                || inclusiveForcedEndRevision < exclusiveStartRevision) {
            throw new IllegalArgumentException("signing committed-prefix bounds are invalid");
        }
        boolean empty = inclusiveForcedEndOffset == exclusiveStartOffset;
        boolean endpointEqual = inclusiveForcedEndSequence == exclusiveStartSequence
                && inclusiveForcedEndRevision == exclusiveStartRevision
                && MessageDigest.isEqual(exclusiveStartCommitment,
                        inclusiveForcedEndCommitment);
        if (empty != endpointEqual) {
            throw new IllegalArgumentException("signing committed-prefix endpoints are inconsistent");
        }
        exclusiveStartCommitment = exclusiveStartCommitment.clone();
        inclusiveForcedEndCommitment = inclusiveForcedEndCommitment.clone();
    }

    @Override
    public byte[] exclusiveStartCommitment() {
        return exclusiveStartCommitment.clone();
    }

    @Override
    public byte[] inclusiveForcedEndCommitment() {
        return inclusiveForcedEndCommitment.clone();
    }

    /* default */ boolean isEmpty() {
        return inclusiveForcedEndOffset == exclusiveStartOffset;
    }

    /** Compares the forced-end commitment without exposing or cloning it. */
    /* default */ boolean matchesInclusiveForcedEndCommitment(byte[] expected) {
        return MessageDigest.isEqual(inclusiveForcedEndCommitment,
                Objects.requireNonNull(expected, "expected"));
    }

    private static void requireCommitment(byte[] commitment) {
        Objects.requireNonNull(commitment, "commitment");
        if (commitment.length != SigningFormatSupport.SHA_256_BYTES) {
            throw new IllegalArgumentException("signing committed-prefix commitment is invalid");
        }
    }
}
