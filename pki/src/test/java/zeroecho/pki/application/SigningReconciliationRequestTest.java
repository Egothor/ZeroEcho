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
package zeroecho.pki.application;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import zeroecho.core.io.CancellationSignal;

final class SigningReconciliationRequestTest {

    @Test
    void continuationFactoryCarriesCompleteCycleAndValidatesNewBounds() {
        SigningReconciliationContinuation continuation = new SigningReconciliationContinuation(
                Optional.of("B"), Optional.of("Z"), Optional.of("M"), true);
        SigningReconciliationResult previous = new SigningReconciliationResult(continuation,
                1, 0, 1, 1, false);
        Instant deadline = Instant.parse("2026-08-12T12:00:00Z");
        Duration callTimeout = Duration.ofSeconds(3);
        CancellationSignal cancellation = () -> false;

        SigningReconciliationRequest request = SigningReconciliationRequest.continueFrom(previous,
                17, 5, deadline, callTimeout, cancellation);

        assertSame(continuation, request.continuation());
        assertEquals(17, request.maximumRecords());
        assertEquals(5, request.maximumProviderCalls());
        assertEquals(deadline, request.deadline());
        assertEquals(callTimeout, request.providerCallTimeout());
        assertSame(cancellation, request.cancellation());
        assertThrows(IllegalArgumentException.class,
                () -> SigningReconciliationRequest.continueFrom(previous, 3, 4, deadline,
                        callTimeout, cancellation));
        assertThrows(NullPointerException.class,
                () -> SigningReconciliationRequest.continueFrom(null, 3, 2, deadline,
                        callTimeout, cancellation));
    }

    @Test
    void continuationRejectsContradictoryOrderingAndAcceptsCycleBoundaries() {
        assertThrows(IllegalArgumentException.class,
                () -> continuation("Z", "B", null, false));
        assertThrows(IllegalArgumentException.class,
                () -> continuation("B", "M", "Z", false));
        assertThrows(IllegalArgumentException.class,
                () -> continuation("A", "Z", "B", false));
        assertThrows(IllegalArgumentException.class,
                () -> continuation("M", "Z", "B", true));
        assertThrows(IllegalArgumentException.class,
                () -> new SigningReconciliationContinuation(Optional.empty(), Optional.of("Z"),
                        Optional.of("B"), true));

        assertDoesNotThrow(() -> continuation("B", "B", null, false));
        assertDoesNotThrow(() -> continuation("B", "Z", "B", false));
        assertDoesNotThrow(() -> continuation("B", "Z", "B", true));
        assertDoesNotThrow(() -> continuation("Z", "Z", "B", true));
        assertDoesNotThrow(() -> continuation("B", "B", "B", true));
    }

    private static SigningReconciliationContinuation continuation(String cursor, String highWatermark,
            String wrapUpperBound, boolean wrapped) {
        return new SigningReconciliationContinuation(Optional.of(cursor), Optional.of(highWatermark),
                Optional.ofNullable(wrapUpperBound), wrapped);
    }
}
