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
package zeroecho.pki.impl.core.signing;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import zeroecho.pki.api.PkiId;

/**
 * Bounded authority-round-robin queue retaining only operation and authority
 * identifiers.
 *
 * <p>This class is thread-confined. A later reactor may invoke it only while
 * holding its own scheduling monitor. Enqueue and dequeue are expected/amortized
 * {@code O(1)}; retained auxiliary memory is {@code O(P)} for capacity {@code P}.
 * No workflow, envelope, payload, weight, or persistent state is retained.</p>
 */
final class AuthorityFairQueue {
    private static final int MAXIMUM_CAPACITY = 4096;

    private final int capacity;
    private final Map<PkiId, AuthorityBucket> byAuthority = new HashMap<>();
    private final Deque<AuthorityBucket> authorityRing = new ArrayDeque<>();
    private final Set<PkiId> operations = new HashSet<>();

    /**
     * Creates an empty queue.
     *
     * @param capacity maximum buffered operations, from 1 through 4096
     * @throws IllegalArgumentException if the capacity is outside its range
     */
    /* default */ AuthorityFairQueue(int capacity) {
        if (capacity < 1 || capacity > MAXIMUM_CAPACITY) {
            throw new IllegalArgumentException("Authority fair-queue capacity is invalid");
        }
        this.capacity = capacity;
    }

    /**
     * Adds one operation to the tail of its authority's FIFO bucket. A newly
     * observed authority joins the tail of the current authority round.
     *
     * @param operationId unique buffered operation identifier
     * @param fairnessAuthorityId scheduling authority identifier
     * @throws NullPointerException if either identifier is {@code null}
     * @throws IllegalArgumentException if the operation is already buffered
     * @throws IllegalStateException if the queue is full
     */
    /* default */ void enqueue(PkiId operationId, PkiId fairnessAuthorityId) {
        PkiId operation = Objects.requireNonNull(operationId, "operationId");
        PkiId authority = Objects.requireNonNull(fairnessAuthorityId, "fairnessAuthorityId");
        if (operations.contains(operation)) {
            throw new IllegalArgumentException("Authority fair queue contains the operation");
        }
        if (operations.size() == capacity) {
            throw new IllegalStateException("Authority fair queue is full");
        }
        AuthorityBucket bucket = byAuthority.get(authority);
        if (bucket == null) {
            bucket = new AuthorityBucket(authority);
            byAuthority.put(authority, bucket);
            authorityRing.addLast(bucket);
        }
        bucket.operations.addLast(operation);
        operations.add(operation);
    }

    /**
     * Removes the head operation from the current authority and rotates a still
     * nonempty authority to the tail.
     *
     * @return next operation identifier, or {@code null} when empty
     */
    /* default */ PkiId poll() {
        AuthorityBucket bucket = authorityRing.pollFirst();
        if (bucket == null) {
            return null;
        }
        PkiId operation = bucket.operations.removeFirst();
        operations.remove(operation);
        if (bucket.operations.isEmpty()) {
            byAuthority.remove(bucket.authorityId, bucket);
        } else {
            authorityRing.addLast(bucket);
        }
        return operation;
    }

    /** Returns the exact number of buffered operations. */
    /* default */ int size() {
        return operations.size();
    }

    /** Returns the exact number of operations that may still be buffered. */
    /* default */ int remainingCapacity() {
        return capacity - operations.size();
    }

    /** Removes every operation and authority bucket for immediate reuse. */
    /* default */ void clear() {
        operations.clear();
        byAuthority.clear();
        authorityRing.clear();
    }

    /** One active authority's FIFO operations. */
    private static final class AuthorityBucket {
        private final PkiId authorityId;
        private final Deque<PkiId> operations = new ArrayDeque<>();

        private AuthorityBucket(PkiId authorityId) {
            this.authorityId = authorityId;
        }
    }
}
