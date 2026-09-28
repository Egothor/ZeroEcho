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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import zeroecho.pki.api.PkiId;

final class AuthorityFairQueueTest {
    private static final PkiId AUTHORITY_A = id("authority-a");
    private static final PkiId AUTHORITY_B = id("authority-b");
    private static final PkiId AUTHORITY_C = id("authority-c");

    @Test
    void rotatesAuthoritiesAndPreservesPerAuthorityFifo() {
        AuthorityFairQueue queue = new AuthorityFairQueue(5);
        queue.enqueue(id("a-1"), AUTHORITY_A);
        queue.enqueue(id("b-1"), AUTHORITY_B);
        queue.enqueue(id("c-1"), AUTHORITY_C);
        queue.enqueue(id("a-2"), AUTHORITY_A);
        queue.enqueue(id("b-2"), AUTHORITY_B);

        assertEquals(List.of(id("a-1"), id("b-1"), id("c-1"), id("a-2"), id("b-2")),
                drain(queue));
    }

    @Test
    void lateAuthorityJoinsTailOfCurrentRound() {
        AuthorityFairQueue queue = new AuthorityFairQueue(5);
        queue.enqueue(id("a-1"), AUTHORITY_A);
        queue.enqueue(id("a-2"), AUTHORITY_A);
        queue.enqueue(id("b-1"), AUTHORITY_B);
        queue.enqueue(id("b-2"), AUTHORITY_B);
        assertEquals(id("a-1"), queue.poll());
        queue.enqueue(id("c-1"), AUTHORITY_C);

        assertEquals(List.of(id("b-1"), id("a-2"), id("c-1"), id("b-2")),
                drain(queue));
    }

    @Test
    void singleAuthorityRemainsFifo() {
        AuthorityFairQueue queue = new AuthorityFairQueue(3);
        queue.enqueue(id("a-1"), AUTHORITY_A);
        queue.enqueue(id("a-2"), AUTHORITY_A);
        queue.enqueue(id("a-3"), AUTHORITY_A);

        assertEquals(List.of(id("a-1"), id("a-2"), id("a-3")), drain(queue));
    }

    @Test
    void duplicateOperationIsRejectedWithoutIdentifierDisclosure() {
        AuthorityFairQueue queue = new AuthorityFairQueue(2);
        PkiId operation = id("secret-operation");
        queue.enqueue(operation, AUTHORITY_A);

        IllegalArgumentException failure = assertThrows(IllegalArgumentException.class,
                () -> queue.enqueue(operation, AUTHORITY_B));
        assertFalse(failure.getMessage().contains(operation.value()));
        assertEquals(1, queue.size());
        assertEquals(1, queue.remainingCapacity());
    }

    @Test
    void fullQueueRejectsWithoutChangingExactCountsOrLeakingIdentifiers() {
        AuthorityFairQueue queue = new AuthorityFairQueue(2);
        queue.enqueue(id("a-1"), AUTHORITY_A);
        queue.enqueue(id("b-1"), AUTHORITY_B);

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> queue.enqueue(id("secret-overflow"), AUTHORITY_C));
        assertFalse(failure.getMessage().contains("secret-overflow"));
        assertEquals(2, queue.size());
        assertEquals(0, queue.remainingCapacity());
    }

    @Test
    void drainedQueueRemovesAuthorityStateAndCanBeReused() {
        AuthorityFairQueue queue = new AuthorityFairQueue(2);
        queue.enqueue(id("a-1"), AUTHORITY_A);
        assertEquals(id("a-1"), queue.poll());
        assertNull(queue.poll());
        assertEquals(0, queue.size());
        assertEquals(2, queue.remainingCapacity());

        queue.enqueue(id("a-2"), AUTHORITY_A);
        queue.enqueue(id("b-1"), AUTHORITY_B);
        assertEquals(List.of(id("a-2"), id("b-1")), drain(queue));
    }

    @Test
    void clearReleasesAllBucketsOperationsAndCapacity() {
        AuthorityFairQueue queue = new AuthorityFairQueue(3);
        queue.enqueue(id("a-1"), AUTHORITY_A);
        queue.enqueue(id("b-1"), AUTHORITY_B);
        queue.clear();

        assertNull(queue.poll());
        assertEquals(0, queue.size());
        assertEquals(3, queue.remainingCapacity());
        queue.enqueue(id("a-1"), AUTHORITY_C);
        assertEquals(id("a-1"), queue.poll());
    }

    @Test
    void validatesCapacityAndIdentifiers() {
        assertThrows(IllegalArgumentException.class, () -> new AuthorityFairQueue(0));
        assertThrows(IllegalArgumentException.class, () -> new AuthorityFairQueue(4097));
        AuthorityFairQueue maximum = new AuthorityFairQueue(4096);
        assertEquals(4096, maximum.remainingCapacity());

        AuthorityFairQueue queue = new AuthorityFairQueue(1);
        assertThrows(NullPointerException.class, () -> queue.enqueue(null, AUTHORITY_A));
        assertThrows(NullPointerException.class, () -> queue.enqueue(id("operation"), null));
        assertEquals(0, queue.size());
    }

    @Test
    void everyBufferedAuthorityProgressesWithinEachFiniteRound() {
        AuthorityFairQueue queue = new AuthorityFairQueue(8);
        queue.enqueue(id("a-1"), AUTHORITY_A);
        queue.enqueue(id("a-2"), AUTHORITY_A);
        queue.enqueue(id("a-3"), AUTHORITY_A);
        queue.enqueue(id("b-1"), AUTHORITY_B);
        queue.enqueue(id("b-2"), AUTHORITY_B);
        queue.enqueue(id("c-1"), AUTHORITY_C);
        queue.enqueue(id("c-2"), AUTHORITY_C);
        queue.enqueue(id("c-3"), AUTHORITY_C);

        assertEquals(List.of(id("a-1"), id("b-1"), id("c-1"), id("a-2"),
                id("b-2"), id("c-2"), id("a-3"), id("c-3")), drain(queue));
    }

    private static List<PkiId> drain(AuthorityFairQueue queue) {
        List<PkiId> result = new ArrayList<>();
        PkiId operation;
        while ((operation = queue.poll()) != null) {
            result.add(operation);
        }
        return List.copyOf(result);
    }

    private static PkiId id(String value) {
        return new PkiId(value);
    }
}
