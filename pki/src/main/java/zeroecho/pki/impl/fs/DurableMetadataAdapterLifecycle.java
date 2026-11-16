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

/**
 * Shared store lifecycle and exact-instance resource authority.
 */
final class DurableMetadataAdapterLifecycle {
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition operationsFinished = lock.newCondition();
    private final Set<ManagedResource> resources =
            Collections.newSetFromMap(new IdentityHashMap<>());
    private State state = State.OPEN;
    private boolean closing;
    private int activeOperations;

    /**
     * Creates and registers an exact resource instance while holding the short lifecycle lock.
     *
     * <p>A null allocation result is rejected before registration.</p>
     *
     * @param <T> managed resource type
     * @param factory checked resource allocator invoked only while ordinary store access is permitted
     * @return new registered resource; store closure forcibly releases still-registered resources
     * @throws NullPointerException if the factory or its created resource is null
     * @throws IllegalStateException if the store is closing, closed or requires recovery
     * @throws IOException if resource allocation fails
     */
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

    /**
     * Runs one checked read operation while ordinary access is protected by the lifecycle lock.
     *
     * @param <T> operation result type
     * @param operation checked synchronous read callback invoked under the lifecycle lock
     * @return callback result, including null if returned by the operation
     * @throws NullPointerException if a required callback is null
     * @throws IllegalStateException if the store is closing, closed or requires recovery
     * @throws IOException if the checked callback fails
     */
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

    /**
     * Requires ordinary access to be permitted at the current lifecycle boundary.
     *
     * @throws IllegalStateException if the store is closing, closed or requires recovery
     */
    /* default */ void verifyOpen() {
        lock.lock();
        try {
            requireOpenLocked();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Registers one in-flight ordinary operation before work leaves the lifecycle lock.
     *
     * @return one-shot operation reservation that must be completed or cancelled
     * @throws IllegalStateException if the store is closing, closed or requires recovery
     */
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

    /**
     * Registers one cleanup operation even when recovery is required, provided closure has not begun.
     *
     * @return one-shot cleanup reservation that must be consumed
     * @throws IllegalStateException if the store is closing or closed
     */
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

    /**
     * Returns the number of in-flight operation reservations under the lifecycle lock.
     *
     * @return current ordinary and cleanup reservations not yet consumed
     */
    /* default */ int activeOperationCount() {
        lock.lock();
        try {
            return activeOperations;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Waits uninterruptibly until closure begins or the store is already closed.
     *
     * <p>The caller's interrupt status is preserved by the condition wait.</p>
     *
     */
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

    /**
     * Removes only the identical registered resource instance from store-close ownership.
     *
     * @param resource exact resource instance to unregister; absent or null instances have no effect
     */
    /* default */ void unregister(ManagedResource resource) {
        lock.lock();
        try {
            resources.remove(resource);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Fences new ordinary operations after uncertainty while retaining cleanup authority.
     *
     * <p>Only an OPEN state changes to RECOVERY_REQUIRED; closure state is retained.</p>
     *
     */
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

    /**
     * Stops admission, waits for all operation reservations, then releases managed resources and the engine.
     *
     * <p>The wait is uninterruptible. Repeated calls after CLOSED return without closing again.</p>
     *
     * @param engine owned engine to close after detached resource cleanup
     * @throws NullPointerException if the engine is null when cleanup reaches it
     * @throws IOException if a managed resource or the engine fails to close; later close failures are suppressed
     */
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

    /**
     * Accumulates checked cleanup failures while retaining the first failure as primary.
     *
     * @param first primary cleanup failure, or null if none
     * @param later subsequent failure to suppress, or null if none
     * @return first non-null failure, with a later non-null failure attached as suppressed
     * @throws IllegalArgumentException if both arguments are the identical non-null exception
     */
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

    /**
     * One-shot store operation authority consumed under the lifecycle lock.
     */
    /* default */
    final class OperationReservation {
        private boolean consumed;

        /**
         * Consumes a reservation and selects its accepted or rejected callback atomically under the lifecycle lock.
         *
         * <p>Consumption and waiter notification occur even if the callback throws.</p>
         *
         * @param accepted callback run only if ordinary access remains open
         * @param rejected callback run if closing, closed or recovery-required state rejects completion
         * @return true if the accepted callback was selected; false if the rejected callback was selected
         * @throws NullPointerException if a required callback is null
         * @throws IllegalStateException if this reservation was already consumed
         * @throws RuntimeException if the selected callback fails; the reservation is still consumed
         */
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

        /**
         * Consumes a reservation after executing its cleanup callback regardless of current store state.
         *
         * <p>Consumption and waiter notification occur even if the callback throws.</p>
         *
         * @param cleanup synchronous cleanup callback run under the lifecycle lock
         * @throws NullPointerException if a required callback is null
         * @throws IllegalStateException if this reservation was already consumed
         * @throws RuntimeException if the selected callback fails; the reservation is still consumed
         */
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

        /**
         * Consumes a reservation after its terminal callback regardless of ordinary admission state.
         *
         * <p>Consumption and waiter notification occur even if the callback throws.</p>
         *
         * @param completion synchronous terminal completion callback run under the lifecycle lock
         * @throws NullPointerException if a required callback is null
         * @throws IllegalStateException if this reservation was already consumed
         * @throws RuntimeException if the selected callback fails; the reservation is still consumed
         */
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

    /**
     * Internal resource release avoids imposing another public close contract.
     */
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

    /**
     * Checked lifecycle operation performed under the short store lock.
     *
     * @param <T> result type returned by the checked lifecycle operation
     */
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

    /**
     * Closed adapter lifecycle states distinct from an in-progress close.
     */
    private enum State {
        OPEN,
        RECOVERY_REQUIRED,
        CLOSED
    }
}
