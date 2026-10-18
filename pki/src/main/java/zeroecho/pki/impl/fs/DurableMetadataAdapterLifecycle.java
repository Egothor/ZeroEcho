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
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/** Shared store lifecycle and exact-instance resource authority. */
final class DurableMetadataAdapterLifecycle {
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition operationsFinished = lock.newCondition();
    private final Set<ManagedResource> resources =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private State state = State.OPEN;
    private boolean closing;
    private int activeOperations;

    /* default */ <T extends ManagedResource> T openManaged(CheckedFactory<T> factory)
            throws IOException {
        Objects.requireNonNull(factory, "factory");
        lock.lock();
        try {
            requireOpenLocked();
            T result = Objects.requireNonNull(factory.create(), "managed resource");
            resources.add(result);
            return result;
        } finally {
            lock.unlock();
        }
    }

    /* default */ <T> T read(CheckedFactory<T> operation) throws IOException {
        Objects.requireNonNull(operation, "operation");
        lock.lock();
        try {
            requireOpenLocked();
            return operation.create();
        } finally {
            lock.unlock();
        }
    }

    /* default */ void verifyOpen() {
        lock.lock();
        try {
            requireOpenLocked();
        } finally {
            lock.unlock();
        }
    }

    /* default */ OperationReservation beginOperation() {
        lock.lock();
        try {
            requireOpenLocked();
            activeOperations++;
            return new OperationReservation();
        } finally {
            lock.unlock();
        }
    }

    /* default */ OperationReservation beginCleanupOperation() {
        lock.lock();
        try {
            requireNotClosingLocked();
            activeOperations++;
            return new OperationReservation();
        } finally {
            lock.unlock();
        }
    }

    /* default */ int activeOperationCount() {
        lock.lock();
        try {
            return activeOperations;
        } finally {
            lock.unlock();
        }
    }

    /* default */ void awaitClosing() {
        lock.lock();
        try {
            while (!closing && state != State.CLOSED) {
                operationsFinished.awaitUninterruptibly();
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ void unregister(ManagedResource resource) {
        lock.lock();
        try {
            resources.remove(resource);
        } finally {
            lock.unlock();
        }
    }

    /* default */ void recoveryRequired() {
        lock.lock();
        try {
            if (state == State.OPEN) {
                state = State.RECOVERY_REQUIRED;
            }
        } finally {
            lock.unlock();
        }
    }

    /* default */ void close(DurableMetadataStoreEngine engine) throws IOException {
        List<ManagedResource> detached;
        lock.lock();
        try {
            if (state == State.CLOSED) {
                return;
            }
            closing = true;
            operationsFinished.signalAll();
            while (activeOperations != 0) {
                operationsFinished.awaitUninterruptibly();
            }
            detached = List.copyOf(resources);
            resources.clear();
            state = State.CLOSED;
        } finally {
            lock.unlock();
        }
        IOException failure = closeManaged(detached);
        try {
            engine.close();
        } catch (IOException cleanup) {
            failure = append(failure, cleanup);
        }
        if (failure != null) {
            throw failure;
        }
    }

    private static IOException closeManaged(List<ManagedResource> resources) {
        IOException failure = null;
        for (ManagedResource resource : resources) {
            failure = append(failure, resource.forceClose());
        }
        return failure;
    }

    /* default */ static IOException append(IOException first, IOException later) {
        if (later == null) {
            return first;
        }
        if (first == null) {
            return later;
        }
        first.addSuppressed(later);
        return first;
    }

    private void requireOpenLocked() {
        requireNotClosingLocked();
        if (state == State.RECOVERY_REQUIRED) {
            throw new IllegalStateException("Durable transactional metadata store requires recovery");
        }
    }

    private void requireNotClosingLocked() {
        if (state == State.CLOSED || closing) {
            throw new IllegalStateException("Durable transactional metadata store is closed");
        }
    }

    /** One-shot store operation authority consumed under the lifecycle lock. */
    /* default */
    final class OperationReservation {
        private boolean consumed;

        /* default */ boolean finish(Runnable accepted, Runnable rejected) {
            Objects.requireNonNull(accepted, "accepted");
            Objects.requireNonNull(rejected, "rejected");
            lock.lock();
            try {
                requireUnconsumed();
                boolean accept = state == State.OPEN && !closing;
                if (accept) {
                    accepted.run();
                } else {
                    rejected.run();
                }
                return accept;
            } finally {
                consumeLocked();
                lock.unlock();
            }
        }

        /* default */ void cancel(Runnable cleanup) {
            Objects.requireNonNull(cleanup, "cleanup");
            lock.lock();
            try {
                requireUnconsumed();
                cleanup.run();
            } finally {
                consumeLocked();
                lock.unlock();
            }
        }

        /* default */ void finishTerminal(Runnable completion) {
            Objects.requireNonNull(completion, "completion");
            lock.lock();
            try {
                requireUnconsumed();
                completion.run();
            } finally {
                consumeLocked();
                lock.unlock();
            }
        }

        private void requireUnconsumed() {
            if (consumed) {
                throw new IllegalStateException("Metadata operation reservation is already consumed");
            }
        }

        private void consumeLocked() {
            if (!consumed) {
                consumed = true;
                activeOperations--;
                operationsFinished.signalAll();
            }
        }
    }

    /** Internal resource release avoids imposing another public close contract. */
    /* default */
    @FunctionalInterface
    interface ManagedResource {
        /**
         * Releases the resource without requiring caller thread ownership.
         *
         * @return checked cleanup failure, or {@code null}
         */
        IOException forceClose();
    }

    /** Checked lifecycle operation performed under the short store lock. */
    /* default */
    @FunctionalInterface
    interface CheckedFactory<T> {
        /**
         * Performs one checked operation.
         *
         * @return operation result
         * @throws IOException when the operation fails
         */
        T create() throws IOException;
    }

    /** Closed adapter lifecycle states distinct from an in-progress close. */
    private enum State {
        OPEN,
        RECOVERY_REQUIRED,
        CLOSED
    }
}
