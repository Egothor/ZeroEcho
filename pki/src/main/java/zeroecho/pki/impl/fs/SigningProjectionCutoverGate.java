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

import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/** Drains projection snapshot capture before an index-root cutover. */
final class SigningProjectionCutoverGate {
    private final ReentrantLock lock = new ReentrantLock(true);
    private final Condition admissionAvailable = lock.newCondition();
    private final Condition capturesDrained = lock.newCondition();
    private int activeCaptures;
    private boolean cutover;
    private boolean closed;

    /* default */ Capture enter() throws InterruptedException {
        lock.lockInterruptibly();
        try {
            while (cutover && !closed) {
                admissionAvailable.await();
            }
            requireOpen();
            activeCaptures++;
            return new Capture(this);
        } finally {
            lock.unlock();
        }
    }

    /* default */ Capture tryEnter() {
        lock.lock();
        try {
            requireOpen();
            if (cutover) {
                return null;
            }
            activeCaptures++;
            return new Capture(this);
        } finally {
            lock.unlock();
        }
    }

    /* default */ void closeCutoverAndDrain() throws InterruptedException {
        lock.lockInterruptibly();
        try {
            requireOpen();
            if (cutover) {
                throw new IllegalStateException("signing projection cutover overlaps");
            }
            cutover = true;
            while (activeCaptures != 0 && !closed) {
                capturesDrained.await();
            }
            requireOpen();
        } finally {
            lock.unlock();
        }
    }

    /* default */ void reopenCutover() {
        lock.lock();
        try {
            if (!closed && cutover) {
                cutover = false;
                admissionAvailable.signalAll();
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ void close() {
        lock.lock();
        try {
            closed = true;
            cutover = false;
            admissionAvailable.signalAll();
            capturesDrained.signalAll();
        } finally {
            lock.unlock();
        }
    }

    private void release() {
        lock.lock();
        try {
            if (activeCaptures <= 0) {
                throw new IllegalStateException("signing projection capture accounting is inconsistent");
            }
            activeCaptures--;
            if (activeCaptures == 0) {
                capturesDrained.signalAll();
            }
        } finally {
            lock.unlock();
        }
    }

    private void requireOpen() {
        if (closed) {
            throw new IllegalStateException("Metadata store requires recovery");
        }
    }

    /** One short-lived projection capture token. */
    /* default */ static final class Capture implements AutoCloseable {
        private final SigningProjectionCutoverGate owner;
        private final AtomicBoolean active = new AtomicBoolean(true);

        private Capture(SigningProjectionCutoverGate owner) {
            this.owner = owner;
        }

        @Override
        public void close() {
            if (active.compareAndSet(true, false)) {
                owner.release();
            }
        }
    }
}
