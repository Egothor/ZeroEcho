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

package zeroecho.pki.spi.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;

final class SignWorkflowStoreDuePageTest {
    private static final PkiId FIRST = id(1L, '1');
    private static final PkiId SECOND = id(2L, '2');
    private static final SignWorkflowStore.SchedulingCoordinates SCHEDULING =
            new SignWorkflowStore.SchedulingCoordinates(
                    new KeyRef("test-key"), new PkiId("test-authority"));

    @Test
    void snapshotsCandidatesAndAcceptsConsistentLightweightPage() {
        List<SignWorkflowStore.DueCandidate> source = new ArrayList<>();
        source.add(new SignWorkflowStore.DueCandidate(FIRST, SCHEDULING, true));
        source.add(new SignWorkflowStore.DueCandidate(SECOND, SCHEDULING, false));

        SignWorkflowStore.DuePage page = new SignWorkflowStore.DuePage(source,
                Optional.of(SECOND.value()), 1, false, Optional.of(SECOND.value()));
        source.clear();

        assertEquals(List.of(new SignWorkflowStore.DueCandidate(FIRST, SCHEDULING, true),
                new SignWorkflowStore.DueCandidate(SECOND, SCHEDULING, false)), page.candidates());
        assertEquals(List.of("operationId", "scheduling", "malformed"),
                Arrays.stream(SignWorkflowStore.DueCandidate.class.getRecordComponents())
                        .map(java.lang.reflect.RecordComponent::getName).toList());
        assertThrows(UnsupportedOperationException.class,
                () -> page.candidates().add(new SignWorkflowStore.DueCandidate(
                        SECOND, SCHEDULING, false)));
    }

    @Test
    void rejectsNoncanonicalIdsOrderDuplicatesCursorCountsAndWatermark() {
        SignWorkflowStore.DueCandidate first = new SignWorkflowStore.DueCandidate(
                FIRST, SCHEDULING, false);
        SignWorkflowStore.DueCandidate second = new SignWorkflowStore.DueCandidate(
                SECOND, SCHEDULING, true);

        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DueCandidate(
                        new PkiId("not-signing"), SCHEDULING, false));
        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DueCandidate(
                        new PkiId("zsign:v1:test:01:" + "1".repeat(32)), SCHEDULING, false));
        assertThrows(NullPointerException.class,
                () -> new SignWorkflowStore.DueCandidate(FIRST, null, false));
        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DuePage(List.of(second, first),
                        Optional.of(FIRST.value()), 1, false, Optional.of(SECOND.value())));
        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DuePage(List.of(first, first),
                        Optional.of(FIRST.value()), 0, false, Optional.of(SECOND.value())));
        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DuePage(List.of(first),
                        Optional.of(SECOND.value()), 0, false, Optional.of(SECOND.value())));
        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DuePage(List.of(first, second),
                        Optional.of(SECOND.value()), 0, false, Optional.of(SECOND.value())));
        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DuePage(List.of(second),
                        Optional.of(SECOND.value()), 1, false, Optional.of(FIRST.value())));
        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DuePage(List.of(), Optional.empty(), 0,
                        true, Optional.of("not-signing")));
        assertThrows(IllegalArgumentException.class,
                () -> new SignWorkflowStore.DuePage(List.of(), Optional.of(FIRST.value()),
                        0, true, Optional.of(FIRST.value())));
    }

    private static PkiId id(long epochMillis, char nonce) {
        return new PkiId("zsign:v1:test:" + epochMillis + ':' + String.valueOf(nonce).repeat(32));
    }
}
