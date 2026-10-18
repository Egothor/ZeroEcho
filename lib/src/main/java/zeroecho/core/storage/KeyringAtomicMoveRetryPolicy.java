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

package zeroecho.core.storage;

import java.util.Locale;
import java.util.Objects;

/** Immutable, package-local policy for retrying transient atomic-move access denial. */
record KeyringAtomicMoveRetryPolicy(int attempts, long delayMillis, Pause pause) {
    /* default */ static final KeyringAtomicMoveRetryPolicy PLATFORM = forPlatform(
            System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows"), Thread::sleep); // NOPMD DoNotUseThreads - Standalone Java service uses bounded polling/retry or preserves cancellation; no J2EE container.

    KeyringAtomicMoveRetryPolicy {
        if (attempts < 1 || attempts > 5 || delayMillis < 0) {
            throw new IllegalArgumentException("Invalid atomic-move retry policy");
        }
        Objects.requireNonNull(pause, "pause");
    }

    /* default */ static KeyringAtomicMoveRetryPolicy forPlatform(boolean windows, Pause pause) {
        return new KeyringAtomicMoveRetryPolicy(windows ? 5 : 1, 10L, pause);
    }

    /** Injectable wait boundary for deterministic atomic-move retry tests. */
    /* default */ @FunctionalInterface
    interface Pause {
        /** Waits before retrying a transient move failure.
         * @param millis delay in milliseconds
         * @throws InterruptedException if cancellation interrupts the wait
         */
        void await(long millis) throws InterruptedException;
    }
}
