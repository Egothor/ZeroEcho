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
package zeroecho.pki.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.management.ThreadInfo;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Exercises service lock ordering and approval read/modify/write isolation in disposable JVMs.
 *
 * <p>The subprocess boundary lets the original intrinsic-monitor deadlock fail a
 * finite assertion without retaining a blocked test worker or an open control log.
 */
class ControlStoreServiceLockingTest {
    @TempDir
    Path directory;

    @Test
    void approvalReadAllowsStoreOwnerToReenterWhileAnotherReaderWaits() throws Exception {
        runProbe("approval");
    }

    @Test
    void breakGlassReadAllowsStoreOwnerToReenterWhileAnotherReaderWaits() throws Exception {
        runProbe("break-glass");
    }

    @Test
    void concurrentOwnDecisionsAcrossServiceInstancesAreAppliedExactlyOnce() throws Exception {
        runProbe("duplicate-decision");
    }

    @Test
    void concurrentQualifiedDecisionsRetainBothVotesAndReachThreshold() throws Exception {
        runProbe("threshold");
    }

    @Test
    void breakGlassRevocationAndExpiryRemainDurableAcrossServiceInstances() throws Exception {
        runProbe("break-glass-lifecycle");
    }

    private void runProbe(String mode) throws Exception {
        Path root = Files.createDirectory(directory.resolve(mode));
        Path output = directory.resolve(mode + ".log");
        String classes = Path.of(ControlStoreServiceLockingTest.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI()).toString();
        String distribution = System.getProperty("server.distributionDirectory");
        if (distribution == null) {
            throw new IllegalStateException("The test requires the server distribution classpath");
        }
        String classpath = classes + File.pathSeparator + Path.of(distribution, "lib", "*");
        Process process = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", classpath, Probe.class.getName(), mode, root.toString())
                .redirectErrorStream(true).redirectOutput(output.toFile()).start();
        boolean completed;
        try {
            completed = process.waitFor(10, TimeUnit.SECONDS);
        } finally {
            if (process.isAlive()) {
                process.destroyForcibly();
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "Locking probe did not terminate after forced cleanup");
            }
        }
        String evidence = Files.readString(output);
        assertTrue(completed, "CONTROL_STORE_LOCKING_COMPLETION_TIMEOUT: " + mode + "\n" + evidence);
        assertEquals(0, process.exitValue(), evidence);
        assertTrue(evidence.contains("LOCKING_PROBE_PASSED " + mode), evidence);
    }

    /**
     * Runs one isolated lock-order or decision-isolation scenario using the real durable store.
     */
    public static final class Probe {
        private Probe() { }

        /**
         * Executes one named regression scenario and returns only after its threads have joined.
         *
         * @param args scenario name followed by an existing isolated output directory
         * @throws Exception if fixture creation, a bounded coordination wait or a domain assertion fails
         */
        public static void main(String[] args) throws Exception {
            try (ServerTestSupport.OpenedStore opened = ServerTestSupport.open(Path.of(args[1]))) {
                opened.store().createPrincipal(ServerTestSupport.principal("requester"));
                opened.store().createPrincipal(ServerTestSupport.principal("approver-a"));
                opened.store().createPrincipal(ServerTestSupport.principal("approver-b"));
                switch (args[0]) {
                    case "approval", "break-glass" -> lockOrder(opened.store(), args[0]);
                    case "duplicate-decision" -> duplicateDecisions(opened.store());
                    case "threshold" -> thresholdDecisions(opened.store());
                    case "break-glass-lifecycle" -> breakGlassLifecycle(opened.store());
                    default -> throw new IllegalArgumentException("Unknown locking scenario");
                }
            }
            System.out.println("LOCKING_PROBE_PASSED " + args[0]);
        }

        private static ApprovalService.Policy policy(int threshold, Set<String> eligible) {
            return new ApprovalService.Policy("locking-policy", threshold, eligible, Set.of(), true,
                    Duration.ofHours(1), true);
        }

        private static void lockOrder(ServerControlStore store, String mode) throws Exception {
            ApprovalService approvals = new ApprovalService(store, ServerTestSupport.CLOCK, event -> { });
            approvals.request("locking-approval", "ca.create", ServerTestSupport.DIGEST,
                    ServerTestSupport.scope(), "requester", policy(1, Set.of("approver-a")));
            BreakGlassService breakGlass = new BreakGlassService(store, ServerTestSupport.CLOCK, event -> { });
            Runnable read = () -> {
                if (mode.equals("approval")) {
                    if (approvals.requireCurrent("locking-approval").state() != ApprovalService.State.PENDING) {
                        throw new AssertionError("Approval read changed its pending state");
                    }
                } else if (!breakGlass.activeFor("requester").grants().isEmpty()) {
                    throw new AssertionError("Empty break-glass authority unexpectedly granted access");
                }
            };
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread reader = Thread.ofPlatform().name("service-reader").unstarted(() -> capture(read, failure));
            synchronized (store) {
                reader.start();
                await(() -> blockedOnStore(reader, store, Thread.currentThread().threadId()),
                        "Reader did not reach the held control-store monitor");
                ThreadInfo blocked = ManagementFactory.getThreadMXBean().getThreadInfo(reader.threadId());
                System.out.println("STORE_OWNER_REENTERING_SERVICE mode=" + mode
                        + " reader=" + blocked.getThreadName() + " state=" + blocked.getThreadState()
                        + " lock=" + blocked.getLockName() + " owner=" + blocked.getLockOwnerId());
                System.out.flush();
                // This is the coordinator's existing store-to-service acquisition order.
                read.run();
            }
            join(reader);
            rethrow(failure);
        }

        private static void duplicateDecisions(ServerControlStore store) throws Exception {
            CountDownLatch firstRead = new CountDownLatch(1);
            CountDownLatch releaseFirst = new CountDownLatch(1);
            ApprovalService first = new ApprovalService(store, ServerTestSupport.CLOCK, event -> { },
                    (request, principal, justification) -> {
                        firstRead.countDown();
                        awaitLatch(releaseFirst);
                        return true;
                    });
            ApprovalService second = new ApprovalService(store, ServerTestSupport.CLOCK, event -> { },
                    (request, principal, justification) -> true);
            first.request("duplicate-approval", "ca.create", ServerTestSupport.DIGEST,
                    ServerTestSupport.scope(), "requester", policy(1, Set.of("requester")));
            AtomicInteger accepted = new AtomicInteger();
            AtomicInteger rejected = new AtomicInteger();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread firstDecision = Thread.ofPlatform().name("first-decision").unstarted(() ->
                    decide(first, "duplicate-approval", "requester", accepted, rejected, failure));
            Thread secondDecision = Thread.ofPlatform().name("second-decision").unstarted(() ->
                    decide(second, "duplicate-approval", "requester", accepted, rejected, failure));
            firstDecision.start();
            try {
                awaitLatch(firstRead);
                secondDecision.start();
                await(() -> !secondDecision.isAlive()
                                || blockedOnStore(secondDecision, store, firstDecision.threadId()),
                        "Second decision neither completed nor waited for the first transaction");
            } finally {
                releaseFirst.countDown();
            }
            join(firstDecision);
            join(secondDecision);
            rethrow(failure);
            ApprovalService.Request retained = first.requireCurrent("duplicate-approval");
            if (accepted.get() != 1 || rejected.get() != 1 || retained.decisions().size() != 1
                    || retained.state() != ApprovalService.State.APPROVED) {
                throw new AssertionError("Concurrent duplicate decisions were not applied exactly once: accepted="
                        + accepted.get() + ", rejected=" + rejected.get() + ", state=" + retained.state());
            }
        }

        private static void thresholdDecisions(ServerControlStore store) throws Exception {
            ApprovalService first = new ApprovalService(store, ServerTestSupport.CLOCK, event -> { });
            ApprovalService second = new ApprovalService(store, ServerTestSupport.CLOCK, event -> { });
            first.request("threshold-approval", "ca.create", ServerTestSupport.DIGEST,
                    ServerTestSupport.scope(), "requester", policy(2, Set.of("approver-a", "approver-b")));
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger accepted = new AtomicInteger();
            AtomicInteger rejected = new AtomicInteger();
            AtomicReference<Throwable> failure = new AtomicReference<>();
            Thread one = Thread.ofPlatform().name("threshold-one").unstarted(() -> {
                awaitLatch(start);
                decide(first, "threshold-approval", "approver-a", accepted, rejected, failure);
            });
            Thread two = Thread.ofPlatform().name("threshold-two").unstarted(() -> {
                awaitLatch(start);
                decide(second, "threshold-approval", "approver-b", accepted, rejected, failure);
            });
            one.start(); two.start(); start.countDown();
            join(one); join(two); rethrow(failure);
            ApprovalService.Request retained = first.requireCurrent("threshold-approval");
            if (accepted.get() != 2 || rejected.get() != 0 || retained.decisions().size() != 2
                    || retained.state() != ApprovalService.State.APPROVED) {
                throw new AssertionError("Concurrent qualified votes were lost or the threshold was not reached");
            }
        }

        private static void breakGlassLifecycle(ServerControlStore store) {
            Instant now = ServerTestSupport.CLOCK.instant();
            BreakGlassService first = new BreakGlassService(store, ServerTestSupport.CLOCK, event -> { });
            BreakGlassService second = new BreakGlassService(store, ServerTestSupport.CLOCK, event -> { });
            store.createBreakGlass(activeGrant("revoked-grant", now));
            synchronized (store) {
                if (first.revoke("revoked-grant", "approver-a").state() != BreakGlassService.State.REVOKED) {
                    throw new AssertionError("Active emergency authorization was not revoked");
                }
            }
            if (second.requireCurrent("revoked-grant").state() != BreakGlassService.State.REVOKED
                    || !second.activeFor("requester").grants().isEmpty()) {
                throw new AssertionError("Another service instance did not observe durable revocation");
            }
            store.createBreakGlass(activeGrant("expired-grant", now));
            BreakGlassService atExpiry = new BreakGlassService(store,
                    Clock.fixed(now.plusSeconds(60), ZoneOffset.UTC), event -> { });
            if (atExpiry.requireCurrent("expired-grant").state() != BreakGlassService.State.EXPIRED
                    || second.requireCurrent("expired-grant").state() != BreakGlassService.State.EXPIRED
                    || !second.activeFor("requester").grants().isEmpty()) {
                throw new AssertionError("An expired emergency authorization was revived by an older clock");
            }
            boolean rejected = false;
            try {
                second.revoke("expired-grant", "approver-a");
            } catch (IllegalStateException expected) {
                rejected = true;
            }
            if (!rejected) { throw new AssertionError("Expiry was replaced with a later revocation"); }
        }

        private static BreakGlassService.Record activeGrant(String identity, Instant now) {
            Permission.Grant grant = ServerTestSupport.grant(identity, "requester", Permission.Effect.ALLOW,
                    Permission.Action.CERTIFICATE_REVOKE, Permission.ResourceType.REVOCATION,
                    ServerTestSupport.scope(), Permission.Relationship.ANY, Permission.DataView.METADATA_REDACTED);
            return new BreakGlassService.Record(identity, "requester", grant, "Isolated lifecycle regression",
                    "approver-a", Optional.empty(), now, Optional.of(now), now.plusSeconds(60),
                    BreakGlassService.State.ACTIVE, ServerTestSupport.DIGEST);
        }

        private static void decide(ApprovalService service, String approvalId, String principal,
                AtomicInteger accepted, AtomicInteger rejected, AtomicReference<Throwable> failure) {
            try {
                service.decide(approvalId, principal, ApprovalService.Choice.APPROVE, "Concurrent locking regression");
                accepted.incrementAndGet();
            } catch (IllegalStateException expected) {
                rejected.incrementAndGet();
            } catch (Throwable unexpected) {
                failure.compareAndSet(null, unexpected);
            }
        }

        private static boolean blockedOnStore(Thread thread, ServerControlStore store, long owner) {
            ThreadInfo info = ManagementFactory.getThreadMXBean().getThreadInfo(thread.threadId());
            return info != null && info.getThreadState() == Thread.State.BLOCKED
                    && info.getLockInfo() != null
                    && info.getLockInfo().getIdentityHashCode() == System.identityHashCode(store)
                    && info.getLockOwnerId() == owner;
        }

        private static void await(BooleanSupplier condition, String message) {
            long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (!condition.getAsBoolean()) {
                if (System.nanoTime() >= until) { throw new AssertionError(message); }
                Thread.onSpinWait();
            }
        }

        private static void awaitLatch(CountDownLatch latch) {
            try {
                if (!latch.await(5, TimeUnit.SECONDS)) { throw new AssertionError("Fixture latch deadline exceeded"); }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new AssertionError("Fixture coordination interrupted", interrupted);
            }
        }

        private static void join(Thread thread) throws InterruptedException {
            thread.join(TimeUnit.SECONDS.toMillis(5));
            if (thread.isAlive()) { throw new AssertionError("Fixture worker did not finish: " + thread.getName()); }
        }

        private static void capture(Runnable action, AtomicReference<Throwable> failure) {
            try { action.run(); } catch (Throwable unexpected) { failure.compareAndSet(null, unexpected); }
        }

        private static void rethrow(AtomicReference<Throwable> failure) {
            if (failure.get() != null) { throw new AssertionError("Concurrent fixture failed", failure.get()); }
        }
    }
}
