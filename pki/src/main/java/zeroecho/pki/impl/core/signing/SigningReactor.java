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
package zeroecho.pki.impl.core.signing;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.KeyRef;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.PkiException;
import zeroecho.pki.api.SigningExecutionException;
import zeroecho.pki.application.PkiSessionConfiguration.SigningCoordinatorLimits;
import zeroecho.pki.application.PkiSessionConfiguration.SigningKeyGroup;
import zeroecho.pki.application.PkiSessionConfiguration.SigningTopology;
import zeroecho.pki.spi.crypto.SigningProvider;
import zeroecho.pki.spi.store.PkiStore;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.SignWorkflowStore;
import zeroecho.pki.spi.store.SignWorkflowStore.Workflow;

/**
 * Bounded topology-aware pull reactor over the authoritative signing backlog.
 *
 * <p>The reactor borrows one store and one provider, owns one scanner and exactly
 * the configured sum of lane threads, and retains {@code O(sum(P) + sum(L))}
 * identifier metadata. Each exact-key route has an independent authority-fair
 * queue and lane pool; unmatched keys use the mandatory catch-all pool. No pool
 * borrows lanes from another pool, and no workflow, envelope, or payload is held
 * in the backlog.</p>
 *
 * <p>Instances are thread-safe. {@link #start()} is one-shot. {@link #close()}
 * closes acceptance before establishing a no-new-claims barrier, then uses one
 * shared deadline to stop all owned daemon threads. The store and provider remain
 * externally owned.</p>
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.AvoidSynchronizedStatement",
        "PMD.CommentRequired", "PMD.CyclomaticComplexity", "PMD.DoNotUseThreads" })
public final class SigningReactor implements AutoCloseable {
    private static final long NO_NANOS = 0L;

    private final PkiStore store;
    private final SigningCoordinatorLimits limits;
    private final SigningStepExecutor stepExecutor;
    private final Map<KeyRef, LanePool> exactRoutes;
    private final List<LanePool> pools;
    private final LanePool catchAll;
    private final Map<PkiId, SignWorkflowStore.SchedulingCoordinates> retained = new HashMap<>();
    private final Object monitor = new Object();
    private final ReentrantLock acceptanceGate = new ReentrantLock(true);
    private final Condition acceptancesDrained = acceptanceGate.newCondition();
    private final AtomicBoolean cancellationRequested = new AtomicBoolean();
    private final CancellationSignal cancellation = cancellationRequested::get;
    private final Thread scanner;
    private final List<Thread> lanes;
    private Lifecycle lifecycle = Lifecycle.NEW;
    private boolean started;
    private boolean acceptanceClosed;
    private int activeAcceptances;
    private boolean wakePending;
    private long progressGeneration;
    private int claimPermits;

    /**
     * Creates a stopped topology reactor borrowing its store and provider.
     *
     * @param store authoritative durable store
     * @param provider shared configured signing provider
     * @param topology final validated routing topology
     * @param outerDriver idempotent outer-terminal continuation
     */
    public SigningReactor(PkiStore store, SigningProvider provider,
            SigningTopology topology, SigningStepExecutor.OuterTerminalDriver outerDriver) {
        this.store = Objects.requireNonNull(store, "store");
        Objects.requireNonNull(topology, "topology");
        this.limits = topology.coordinator();
        this.stepExecutor = new SigningStepExecutor(store, provider,
                limits.providerCallTimeout(), outerDriver);

        Map<KeyRef, LanePool> routes = new HashMap<>();
        List<LanePool> configuredPools = new ArrayList<>(topology.exactGroups().size() + 1);
        List<Thread> configuredLanes = new ArrayList<>();
        int poolIndex = 0;
        for (SigningKeyGroup group : topology.exactGroups()) {
            LanePool pool = createPool(poolIndex++, group.lanePool().prefetchSize(),
                    group.lanePool().laneCount(), configuredLanes);
            configuredPools.add(pool);
            for (KeyRef keyRef : group.keyRefs()) {
                routes.put(keyRef, pool);
            }
        }
        catchAll = createPool(poolIndex, topology.catchAll().prefetchSize(),
                topology.catchAll().laneCount(), configuredLanes);
        configuredPools.add(catchAll);
        exactRoutes = Map.copyOf(routes);
        pools = List.copyOf(configuredPools);
        lanes = List.copyOf(configuredLanes);
        scanner = daemon("zeroecho-signing-topology-scanner", this::coordinate);
    }

    /** Starts the scanner and every configured lane exactly once. */
    public void start() {
        synchronized (monitor) {
            if (lifecycle != Lifecycle.NEW) {
                throw new IllegalStateException("Signing reactor can be started only once");
            }
            started = true;
            lifecycle = Lifecycle.RUNNING;
            scanner.start();
            for (Thread lane : lanes) {
                lane.start();
            }
        }
    }

    /** Rejects acceptance after the reactor begins quiescing. */
    public void requireAccepting() {
        acceptanceGate.lock();
        try {
            if (acceptanceClosed) {
                throw shuttingDown();
            }
        } finally {
            acceptanceGate.unlock();
        }
    }

    /**
     * Commits acceptance under the reactor shutdown gate.
     *
     * @param command exact immutable acceptance command
     * @param transferCustody atomic prepared-candidate custody transfer
     * @return durable acceptance disposition
     */
    public SignWorkflowStore.AcceptanceResult acceptSign(
            SignWorkflowStore.AcceptanceCommand command, Runnable transferCustody) {
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(transferCustody, "transferCustody");
        acquireAcceptancePermit();
        try {
            transferCustody.run();
            return store.acceptSign(command);
        } finally {
            releaseAcceptancePermit();
        }
    }

    /**
     * Co-commits scheduled acceptance under the existing shutdown and custody gate.
     * @param command exact acceptance command
     * @param claim durable scheduled authorization
     * @param transferCustody candidate custody transfer
     * @return authoritative acceptance disposition
     */
    public SignWorkflowStore.AcceptanceResult acceptScheduledSign(SignWorkflowStore.AcceptanceCommand command,
            zeroecho.pki.api.schedule.StatusScheduleState.Execution claim, Runnable transferCustody) {
        Objects.requireNonNull(command, "command");
        Objects.requireNonNull(claim, "claim");
        Objects.requireNonNull(transferCustody, "transferCustody");
        acquireAcceptancePermit();
        try {
            transferCustody.run();
            return store.acceptScheduledSign(command, claim);
        } finally { releaseAcceptancePermit(); }
    }

    /** Coalesces a nonblocking durable-work notification. */
    public void wake() {
        synchronized (monitor) {
            if (lifecycle == Lifecycle.RUNNING || lifecycle == Lifecycle.NEW) {
                wakePending = true;
                monitor.notifyAll();
            }
        }
    }

    /**
     * Waits for the durable outcome of a bounded initial attempt. Store reads occur
     * outside the reactor monitor; a shared generation closes the read-to-wait race.
     * No workflow is retained while sleeping. Cancellation affects only this wait.
     *
     * @param operationId accepted raw bounded operation identity
     * @param waitCancellation cooperative wait cancellation
     * @return current completed/failed-attempt snapshot, or empty when missing or purged
     * @throws IllegalArgumentException if the retained operation uses ordinary mode
     * @throws PkiException if waiting is cancelled or interrupted; interruption is preserved
     * @throws SigningExecutionException if the reactor is shutting down
     */
    // Interruptions retain the interrupt flag and expose a fixed cause-free diagnostic; other failures propagate unchanged.
    @SuppressWarnings("PMD.PreserveStackTrace")
    public Optional<Workflow> awaitBoundedObservation(PkiId operationId, CancellationSignal waitCancellation) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(waitCancellation, "waitCancellation");
        while (true) {
            requireWaitActive(waitCancellation);
            long observedGeneration;
            synchronized (monitor) {
                requireWaitLifecycle();
                observedGeneration = progressGeneration;
            }
            ObservationRead read;
            try {
                read = readBoundedObservation(operationId);
            } catch (RuntimeException failure) {
                for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                    if (cause instanceof MetadataStoreException metadata
                            && metadata.category() == MetadataCommitResult.FailureCategory.CANCELLED) {
                        Thread.currentThread().interrupt();
                        throw new PkiException("Bounded signing observation wait interrupted");
                    }
                }
                throw failure;
            }
            if (read.ready()) {
                return read.result();
            }
            requireWaitActive(waitCancellation);
            synchronized (monitor) {
                requireWaitLifecycle();
                if (progressGeneration != observedGeneration) {
                    continue;
                }
                try {
                    monitor.wait(read.delayNanos() / 1_000_000L, (int) (read.delayNanos() % 1_000_000L));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw new PkiException("Bounded signing observation wait interrupted");
                }
            }
        }
    }

    private ObservationRead readBoundedObservation(PkiId operationId) {
        Optional<Workflow> loaded = store.getSignWorkflow(operationId);
        if (loaded.isEmpty()) {
            return new ObservationRead(true, Optional.empty(), 0L);
        }
        Workflow current = loaded.orElseThrow();
        if (current.mode() != SignWorkflowStore.Mode.BOUNDED_OBSERVATION) {
            throw new IllegalArgumentException("Operation does not use bounded observation");
        }
        if (current.initialAttemptPhase().finished()) {
            return new ObservationRead(true, loaded, 0L);
        }
        Duration remaining = Duration.between(store.signingNow(), current.deadline());
        long delay = remaining.isNegative() || remaining.isZero() ? 1L
                : remaining.compareTo(limits.idlePollInterval()) < 0
                        ? remaining.toNanos() : limits.idlePollInterval().toNanos();
        return new ObservationRead(false, Optional.empty(), delay);
    }

    private static void requireWaitActive(CancellationSignal waitCancellation) {
        if (Thread.currentThread().isInterrupted()) {
            throw new PkiException("Bounded signing observation wait interrupted");
        }
        if (waitCancellation.isCancelled()) {
            throw new PkiException("Bounded signing observation wait cancelled");
        }
    }

    private void requireWaitLifecycle() {
        if (lifecycle == Lifecycle.QUIESCING || lifecycle == Lifecycle.CLOSED) {
            throw shuttingDown();
        }
    }

    private void publishProgress() {
        synchronized (monitor) {
            progressGeneration++;
            monitor.notifyAll();
        }
    }

    /** Pending decisions contain only scalar timing metadata, never a workflow. */
    private record ObservationRead(boolean ready, Optional<Workflow> result, long delayNanos) { }

    /* default */ int retainedIdentifierCount() {
        synchronized (monitor) {
            return retained.size();
        }
    }

    /* default */ List<Thread> ownedThreads() {
        List<Thread> result = new ArrayList<>(lanes.size() + 1);
        result.add(scanner);
        result.addAll(lanes);
        return List.copyOf(result);
    }

    /**
     * Closes acceptance, establishes the claim barrier, cancels active calls, and
     * waits for all owned threads under one common deadline. A timeout leaves the
     * reactor quiescing so a later close can retry without closing borrowed
     * dependencies.
     */
    @Override public void close() {
        long startedAt = System.nanoTime();
        if (!drainAcceptances(startedAt)) {
            throw shutdownTimeout();
        }
        synchronized (monitor) {
            if (lifecycle == Lifecycle.CLOSED) {
                return;
            }
            if (!started) {
                lifecycle = Lifecycle.CLOSED;
                retained.clear();
                clearPools();
                monitor.notifyAll();
                return;
            }
            lifecycle = Lifecycle.QUIESCING;
            cancellationRequested.set(true);
            clearPools();
            monitor.notifyAll();
        }
        scanner.interrupt();
        for (Thread lane : lanes) {
            lane.interrupt();
        }
        boolean stopped = join(scanner, remainingCloseNanos(startedAt));
        for (Thread lane : lanes) {
            stopped &= join(lane, remainingCloseNanos(startedAt));
        }
        if (!stopped) {
            throw shutdownTimeout();
        }
        synchronized (monitor) {
            if (claimPermits != 0) {
                throw new IllegalStateException("Signing claim permit leaked during shutdown");
            }
            lifecycle = Lifecycle.CLOSED;
            retained.clear();
        }
    }

    private void acquireAcceptancePermit() {
        acceptanceGate.lock();
        try {
            if (acceptanceClosed) {
                throw shuttingDown();
            }
            activeAcceptances++;
        } finally {
            acceptanceGate.unlock();
        }
    }

    private void releaseAcceptancePermit() {
        acceptanceGate.lock();
        try {
            activeAcceptances--;
            if (activeAcceptances == 0) {
                acceptancesDrained.signalAll();
            }
        } finally {
            acceptanceGate.unlock();
        }
    }

    private boolean drainAcceptances(long startedAt) {
        acceptanceGate.lock();
        try {
            acceptanceClosed = true;
            long remaining = remainingCloseNanos(startedAt);
            while (activeAcceptances > 0 && remaining > NO_NANOS) {
                try {
                    remaining = acceptancesDrained.awaitNanos(remaining);
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    return false;
                }
            }
            return activeAcceptances == 0;
        } finally {
            acceptanceGate.unlock();
        }
    }

    private static SigningExecutionException shuttingDown() {
        return new SigningExecutionException(
                SigningExecutionException.Classification.SHUTTING_DOWN,
                "Signing runtime is shutting down");
    }

    private static SigningExecutionException shutdownTimeout() {
        return new SigningExecutionException(
                SigningExecutionException.Classification.SHUTDOWN_TIMEOUT,
                "Signing runtime did not stop within its close timeout");
    }

    private long remainingCloseNanos(long startedAt) {
        return Math.max(NO_NANOS, limits.closeTimeout().toNanos()
                - (System.nanoTime() - startedAt));
    }

    private void coordinate() {
        while (running()) {
            fillOneCycle();
            awaitWakeOrPoll();
        }
    }

    private void fillOneCycle() {
        Instant cutoff = store.signingNow();
        Optional<String> cursor = Optional.empty();
        Optional<String> highWatermark = Optional.empty();
        while (running()) {
            int capacity = awaitAggregateCapacity();
            if (capacity == 0) {
                return;
            }
            SignWorkflowStore.DuePage page;
            try {
                page = store.pageDueSignWorkflows(cutoff, cursor, highWatermark,
                        limits.pageSize(), cancellation);
            } catch (RuntimeException failure) {
                return;
            }
            if (highWatermark.isEmpty()) {
                highWatermark = page.highWatermark();
            }
            for (SignWorkflowStore.DueCandidate candidate : page.candidates()) {
                if (!running()) {
                    return;
                }
                if (!candidate.malformed()) {
                    enqueue(candidate);
                }
                cursor = Optional.of(candidate.operationId().value());
            }
            if (page.endReached()) {
                return;
            }
            Optional<String> advanced = page.nextCursor();
            if (advanced.isEmpty() || cursor.isEmpty()) {
                return;
            }
            cursor = advanced;
        }
    }

    private int awaitAggregateCapacity() {
        synchronized (monitor) {
            int remaining = aggregateRemainingCapacity();
            while (lifecycle == Lifecycle.RUNNING && remaining == 0) {
                try {
                    monitor.wait();
                } catch (InterruptedException failure) {
                    if (lifecycle != Lifecycle.RUNNING) {
                        return 0;
                    }
                }
                remaining = aggregateRemainingCapacity();
            }
            return lifecycle == Lifecycle.RUNNING ? remaining : 0;
        }
    }

    private int aggregateRemainingCapacity() {
        int remaining = 0;
        for (LanePool pool : pools) {
            remaining = Math.addExact(remaining, pool.queue.remainingCapacity());
        }
        return remaining;
    }

    private boolean enqueue(SignWorkflowStore.DueCandidate candidate) {
        synchronized (monitor) {
            if (lifecycle != Lifecycle.RUNNING || retained.containsKey(candidate.operationId())) {
                return false;
            }
            LanePool target = route(candidate.scheduling().keyRef());
            if (target.queue.remainingCapacity() == 0) {
                return false;
            }
            retained.put(candidate.operationId(), candidate.scheduling());
            try {
                target.queue.enqueue(candidate.operationId(),
                        candidate.scheduling().fairnessAuthorityId());
            } catch (RuntimeException failure) {
                retained.remove(candidate.operationId());
                throw failure;
            }
            monitor.notifyAll();
            return true;
        }
    }

    private LanePool route(KeyRef keyRef) {
        return exactRoutes.getOrDefault(keyRef, catchAll);
    }

    private void awaitWakeOrPoll() {
        synchronized (monitor) {
            long deadline = System.nanoTime() + limits.idlePollInterval().toNanos();
            while (lifecycle == Lifecycle.RUNNING && !wakePending) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= NO_NANOS) {
                    return;
                }
                try {
                    monitor.wait(remaining / 1_000_000L,
                            (int) (remaining % 1_000_000L));
                } catch (InterruptedException failure) {
                    if (lifecycle != Lifecycle.RUNNING) {
                        return;
                    }
                }
            }
            wakePending = false;
        }
    }

    private void work(LanePool pool) {
        while (running()) {
            PkiId operationId = take(pool);
            if (operationId == null) {
                return;
            }
            boolean rescan = false;
            try {
                rescan = process(pool, operationId);
            } catch (RuntimeException ignored) {
                // Durable state remains authoritative and retryable.
            } finally {
                synchronized (monitor) {
                    retained.remove(operationId);
                    // Readiness must be rescanned after releasing identifier retention.
                    wakePending |= rescan;
                    monitor.notifyAll();
                }
            }
        }
    }

    private PkiId take(LanePool pool) {
        synchronized (monitor) {
            PkiId operationId = pool.queue.poll();
            while (lifecycle == Lifecycle.RUNNING && operationId == null) {
                try {
                    monitor.wait();
                } catch (InterruptedException failure) {
                    if (lifecycle != Lifecycle.RUNNING) {
                        return null;
                    }
                }
                operationId = pool.queue.poll();
            }
            monitor.notifyAll();
            return lifecycle == Lifecycle.RUNNING ? operationId : null;
        }
    }

    private boolean process(LanePool pool, PkiId operationId) {
        Optional<Workflow> loaded = store.getSignWorkflow(operationId);
        if (loaded.isEmpty()) {
            return false;
        }
        Workflow source = loaded.orElseThrow();
        return matchesScheduledPool(pool, source, operationId)
                && stepExecutor.advance(source, this::claim, cancellation, this::publishProgress);
    }

    private boolean matchesScheduledPool(LanePool pool, Workflow workflow,
            PkiId operationId) {
        KeyRef key = workflow.stage().usesProofKey()
                ? workflow.envelope().proofStep().orElseThrow().subjectKeyRef() : workflow.envelope().keyRef();
        synchronized (monitor) {
            SignWorkflowStore.SchedulingCoordinates scheduled = retained.get(operationId);
            return scheduled != null
                    && scheduled.keyRef().equals(key)
                    && scheduled.fairnessAuthorityId().equals(
                            workflow.envelope().fairnessAuthorityId())
                    && route(key).equals(pool);
        }
    }

    private LanePool createPool(int poolIndex, int prefetchSize, int laneCount,
            List<Thread> configuredLanes) {
        return new LanePool(poolIndex, prefetchSize, laneCount, configuredLanes);
    }

    private Optional<Workflow> claim(Workflow workflow) {
        synchronized (monitor) {
            if (lifecycle != Lifecycle.RUNNING) {
                return Optional.empty();
            }
            claimPermits++;
        }
        try {
            Optional<Workflow> claimed = store.claimSignStep(workflow.operationId(),
                    workflow.revision(), limits.claimLease());
            if (claimed.isPresent()) {
                publishProgress();
            }
            synchronized (monitor) {
                return lifecycle == Lifecycle.RUNNING ? claimed : Optional.empty();
            }
        } finally {
            synchronized (monitor) {
                claimPermits--;
                monitor.notifyAll();
            }
        }
    }

    private boolean running() {
        synchronized (monitor) {
            return lifecycle == Lifecycle.RUNNING;
        }
    }

    private void clearPools() {
        for (LanePool pool : pools) {
            pool.queue.clear();
        }
    }

    private static Thread daemon(String name, Runnable action) {
        Thread thread = new Thread(action, name);
        thread.setDaemon(true);
        return thread;
    }

    private static boolean join(Thread thread, long nanos) {
        if (!thread.isAlive()) {
            return true;
        }
        if (nanos <= NO_NANOS) {
            return false;
        }
        try {
            thread.join(nanos / 1_000_000L, (int) (nanos % 1_000_000L));
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            return false;
        }
        return !thread.isAlive();
    }

    /** One isolated routing pool and its fixed lane ownership. */
    private final class LanePool {
        private final AuthorityFairQueue queue;

        private LanePool(int poolIndex, int prefetchSize, int laneCount,
                List<Thread> configuredLanes) {
            queue = new AuthorityFairQueue(prefetchSize);
            for (int laneIndex = 0; laneIndex < laneCount; laneIndex++) {
                configuredLanes.add(daemon("zeroecho-signing-pool-" + poolIndex
                        + "-lane-" + laneIndex, () -> work(this)));
            }
        }
    }

    private enum Lifecycle { NEW, RUNNING, QUIESCING, CLOSED }
}
