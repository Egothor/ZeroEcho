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
package zeroecho.pki.testkit;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import zeroecho.pki.impl.core.async.PkiSigningBus;

/**
 * Simple test-only worker that drives {@link PkiSigningBus} by periodically
 * invoking {@link PkiSigningBus#sweep(Instant)}.
 */
public final class PkiSigningBusWorker implements AutoCloseable {

    private final PkiSigningBus bus;
    private final Duration period;
    private final AtomicBoolean running;
    private final Thread thread;

    /**
     * Creates and starts a worker.
     *
     * @param bus    bus instance (never {@code null})
     * @param period sweep period (must be positive)
     */
    public PkiSigningBusWorker(PkiSigningBus bus, Duration period) {
        this.bus = Objects.requireNonNull(bus, "bus");
        this.period = Objects.requireNonNull(period, "period");
        if (period.isZero() || period.isNegative()) {
            throw new IllegalArgumentException("period must be positive");
        }

        this.running = new AtomicBoolean(true);
        this.thread = new Thread(this::runLoop, "pki-signing-bus-worker");
        this.thread.setDaemon(true);
        this.thread.start();
    }

    private void runLoop() {
        while (running.get()) {
            bus.sweep(Instant.now());
            try {
                Thread.sleep(period.toMillis());
            } catch (InterruptedException ex) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    @Override
    public void close() {
        running.set(false);
        thread.interrupt();
        try {
            thread.join(2_000L);
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        }
    }
}
