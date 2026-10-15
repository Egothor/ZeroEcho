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

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/** Store admission precedes every domain/content lock; no read-to-write upgrades. */
final class StoreMutationBarrier {
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock(true);
    private final AtomicBoolean accepting = new AtomicBoolean(true);

    /* default */ Lease enter() {
        boolean nested = lock.getReadHoldCount() > 0 || lock.isWriteLockedByCurrentThread();
        if (!nested && !accepting.get()) { throw new IllegalStateException("Store is closing"); }
        Lock shared = lock.readLock();
        shared.lock();
        if (!nested && !accepting.get()) {
            shared.unlock();
            throw new IllegalStateException("Store is closing");
        }
        return new Lease(shared);
    }

    /* default */ Lease freeze() {
        if (lock.getReadHoldCount() > 0 && !lock.isWriteLockedByCurrentThread()) {
            throw new IllegalStateException("Backup cannot start within a store operation");
        }
        Lock exclusive = lock.writeLock();
        exclusive.lock();
        if (!accepting.get()) {
            exclusive.unlock();
            throw new IllegalStateException("Store is closing");
        }
        return new Lease(exclusive);
    }

    /** Deadline-aware search admission, preserving the domain lock order. */
    /* default */ Lease enter(long deadline, zeroecho.core.io.CancellationSignal cancellation) throws java.io.IOException {
        Lock shared = lock.readLock();
        boolean acquired = false;
        try {
            while (!acquired) {
                cancellation.throwIfCancelled();
                if (!accepting.get()) {
                    throw new IllegalStateException("Store is closing");
                }
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    throw new java.io.IOException("Credential search deadline exceeded");
                }
                acquired = shared.tryLock(Math.min(remaining, java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(25)),
                        java.util.concurrent.TimeUnit.NANOSECONDS);
            }
            cancellation.throwIfCancelled();
            if (!accepting.get()) {
                throw new IllegalStateException("Store is closing");
            }
            return new Lease(shared);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt(); // NOPMD DoNotUseThreads - Restores caller cancellation after interruption; this standalone component creates no thread.
            throw new java.io.InterruptedIOException("Credential search interrupted"); // NOPMD PreserveStackTrace - Cancellation retains its public category and interrupt flag without exposing internal I/O state.
        } catch (java.io.IOException | RuntimeException failure) { // NOPMD AvoidCatchingGenericException, ExceptionAsFlowControl - Failure cleanup must retain the original ownership, release and fencing guarantees for unchecked failures too.
            if (acquired) {
                shared.unlock();
            }
            throw failure;
        }
    }

    /* default */ Lease stop() {
        if (lock.getReadHoldCount() > 0) { throw new IllegalStateException("Cannot close within a store operation"); }
        accepting.set(false);
        Lock exclusive = lock.writeLock();
        exclusive.lock();
        return new Lease(exclusive);
    }

    /** Releases exactly one admission or exclusive lifecycle lock acquisition. */
    /* default */ static final class Lease implements AutoCloseable {
        private final Lock held;
        private boolean closed;
        /* default */ Lease(Lock held) { this.held = held; }
        @Override public void close() {
            if (!closed) { held.unlock(); closed = true; }
        }
    }
}
