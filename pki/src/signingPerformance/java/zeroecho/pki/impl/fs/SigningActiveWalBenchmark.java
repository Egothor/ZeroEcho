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

import java.io.IOException;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Deque;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

/** Opt-in open-loop characterization of the production-unwired active WAL. */
@SuppressWarnings({ "PMD.AvoidInstantiatingObjectsInLoops", "PMD.AvoidLiteralsInIfCondition",
        "PMD.CommentRequired", "PMD.DoNotUseThreads", "PMD.SystemPrintln",
        "PMD.UseObjectForClearerAPI", "PMD.AvoidCatchingGenericException" })
public final class SigningActiveWalBenchmark {
    private static final int PAYLOAD_BYTES = 1024;
    private static final int SAMPLE_CAPACITY = 1_000_000;

    private SigningActiveWalBenchmark() {
        // entry point
    }

    /** Runs one diagnostic or acceptance-shape characterization. */
    public static void main(String[] arguments) throws Exception {
        Configuration configuration = Configuration.parse(arguments);
        Result result = run(configuration);
        String json = result.toJson(configuration);
        Path parent = configuration.output().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.writeString(configuration.output(), json,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        System.out.println(json);
    }

    /* default */ static Result run(Configuration configuration) throws Exception {
        Files.createDirectories(configuration.workRoot());
        Path walPath = configuration.workRoot().resolve("active-wal-benchmark.zew");
        Files.deleteIfExists(walPath);
        BenchmarkOperations operations = new BenchmarkOperations(configuration.fakeForce());
        SigningActiveWal.Configuration walConfiguration = new SigningActiveWal.Configuration(
                SigningActiveWal.MAXIMUM_QUEUE_CAPACITY, SigningWalFrameCodec.MAX_BATCH_FRAMES,
                TimeUnit.MILLISECONDS.toNanos(2L),
                (long) SigningActiveWal.MAXIMUM_QUEUE_CAPACITY * PAYLOAD_BYTES,
                SigningActiveWal.MAXIMUM_BATCH_BYTES);
        long gcCountBefore = gcCount();
        long gcTimeBefore = gcTimeMillis();
        long heapBefore = usedHeap();
        Result result;
        try (SigningActiveWal wal = SigningActiveWal.open(walPath,
                new SigningActiveWal.Descriptor(1L, 0L, 0L), walConfiguration,
                operations, System::nanoTime, TimeUnit.NANOSECONDS::timedWait)) {
            runWindow(wal, configuration.rate(), configuration.warmupSeconds(), false);
            SigningActiveWal.Snapshot baseline = wal.snapshot();
            long forcesBefore = operations.forceCalls;
            long allocatedBefore = allocatedBytes();
            result = runWindow(wal, configuration.rate(), configuration.durationSeconds(), true);
            SigningActiveWal.Snapshot snapshot = wal.snapshot();
            result = result.withWal(WalMetrics.between(baseline, snapshot),
                    operations.forceCalls - forcesBefore,
                    Math.max(0L, usedHeap() - heapBefore), gcCount() - gcCountBefore,
                    gcTimeMillis() - gcTimeBefore,
                    Math.max(0L, allocatedBytes() - allocatedBefore));
        }
        return result;
    }

    private static Result runWindow(SigningActiveWal wal, int rate, int seconds,
            boolean retainMetrics) throws InterruptedException, ExecutionException {
        int arrivals = Math.multiplyExact(rate, seconds);
        long period = TimeUnit.SECONDS.toNanos(1L) / rate;
        long start = System.nanoTime();
        Deque<Observation> pending = new ArrayDeque<>(SigningActiveWal.MAXIMUM_QUEUE_CAPACITY);
        Latencies latencies = new Latencies(Math.min(arrivals, SAMPLE_CAPACITY));
        long admitted = 0L;
        long rejected = 0L;
        int maximumBacklog = 0;
        byte[] payload = new byte[PAYLOAD_BYTES];
        for (int index = 0; index < arrivals; index++) {
            long scheduled = start + index * period;
            parkUntil(scheduled);
            drainCompleted(pending, latencies, retainMetrics);
            try {
                SigningActiveWal.Acknowledgement acknowledgement = wal.submit(
                        SigningWalFrameCodec.RecordType.MUTATION,
                        new UUID(0x5A45524FL, index), payload);
                pending.addLast(new Observation(scheduled, acknowledgement));
                admitted++;
                maximumBacklog = Math.max(maximumBacklog, pending.size());
            } catch (SigningActiveWal.OverloadedException overload) {
                rejected++;
            }
        }
        while (!pending.isEmpty()) {
            Observation observation = pending.removeFirst();
            observation.acknowledgement().get();
            if (retainMetrics) {
                latencies.add(Math.max(0L, System.nanoTime() - observation.scheduledNanos()));
            }
        }
        return new Result(arrivals, admitted, rejected, maximumBacklog, latencies.summary(),
                null, 0L, 0L, 0L, 0L, 0L);
    }

    private static void drainCompleted(Deque<Observation> pending, Latencies latencies,
            boolean retainMetrics) throws InterruptedException, ExecutionException {
        while (!pending.isEmpty() && pending.peekFirst().acknowledgement().isDone()) {
            Observation observation = pending.removeFirst();
            observation.acknowledgement().get();
            if (retainMetrics) {
                latencies.add(Math.max(0L, System.nanoTime() - observation.scheduledNanos()));
            }
        }
    }

    private static void parkUntil(long deadline) {
        long remaining;
        while ((remaining = deadline - System.nanoTime()) > 0L) {
            LockSupport.parkNanos(remaining);
        }
    }

    private static long gcCount() {
        long total = 0L;
        for (GarbageCollectorMXBean bean : ManagementFactory.getGarbageCollectorMXBeans()) {
            total += Math.max(0L, bean.getCollectionCount());
        }
        return total;
    }

    private static long gcTimeMillis() {
        long total = 0L;
        for (GarbageCollectorMXBean bean : ManagementFactory.getGarbageCollectorMXBeans()) {
            total += Math.max(0L, bean.getCollectionTime());
        }
        return total;
    }

    private static long usedHeap() {
        Runtime runtime = Runtime.getRuntime();
        return runtime.totalMemory() - runtime.freeMemory();
    }

    private static long allocatedBytes() {
        java.lang.management.ThreadMXBean bean = ManagementFactory.getThreadMXBean();
        if (bean instanceof com.sun.management.ThreadMXBean allocationBean
                && allocationBean.isThreadAllocatedMemorySupported()) {
            return Math.max(0L, allocationBean.getCurrentThreadAllocatedBytes());
        }
        return 0L;
    }

    /* default */ record Configuration(int warmupSeconds, int durationSeconds, int rate,
            boolean fakeForce, Path output, Path workRoot) {
        private static Configuration parse(String[] arguments) {
            int warmup = 2;
            int duration = 10;
            int rate = 1_100;
            boolean fake = false;
            Path output = Path.of("build/reports/signing-performance/active-wal.json");
            Path work = Path.of("build/signing-performance/active-wal");
            for (String argument : arguments) {
                String[] parts = argument.split("=", 2);
                if (parts.length != 2) {
                    throw new IllegalArgumentException("active WAL benchmark argument is invalid");
                }
                switch (parts[0]) {
                    case "--warmupSeconds" -> warmup = Integer.parseInt(parts[1]);
                    case "--durationSeconds" -> duration = Integer.parseInt(parts[1]);
                    case "--rate" -> rate = Integer.parseInt(parts[1]);
                    case "--fakeForce" -> fake = Boolean.parseBoolean(parts[1]);
                    case "--output" -> output = Path.of(parts[1]);
                    case "--workRoot" -> work = Path.of(parts[1]);
                    default -> throw new IllegalArgumentException(
                            "active WAL benchmark argument is unsupported");
                }
            }
            if (warmup < 0 || warmup > 30 || duration <= 0 || duration > 300
                    || rate <= 0 || rate > 1_100) {
                throw new IllegalArgumentException("active WAL benchmark configuration is unsafe");
            }
            return new Configuration(warmup, duration, rate, fake, output, work);
        }
    }

    /* default */ record Result(long scheduled, long admitted, long rejected,
            int maximumBacklog, LatencySummary latency, WalMetrics wal,
            long forceCalls, long heapGrowthBytes, long gcCollections, long gcTimeMillis,
            long submissionThreadAllocatedBytes) {
        private Result withWal(WalMetrics metrics, long actualForces,
                long heapGrowth, long collections, long collectionMillis, long allocatedBytes) {
            return new Result(scheduled, admitted, rejected, maximumBacklog, latency,
                    metrics, actualForces, heapGrowth, collections, collectionMillis,
                    allocatedBytes);
        }

        /* default */ String toJson(Configuration configuration) {
            return "{\"schema\":\"zeroecho-active-wal-characterization-v1\""
                    + ",\"warmupSeconds\":" + configuration.warmupSeconds()
                    + ",\"durationSeconds\":" + configuration.durationSeconds()
                    + ",\"rate\":" + configuration.rate()
                    + ",\"payloadBytes\":" + PAYLOAD_BYTES
                    + ",\"fakeForce\":" + configuration.fakeForce()
                    + ",\"scheduled\":" + scheduled + ",\"admitted\":" + admitted
                    + ",\"rejected\":" + rejected + ",\"maximumBacklog\":" + maximumBacklog
                    + ",\"ackScheduledOriginP50Nanos\":" + latency.p50()
                    + ",\"ackScheduledOriginP95Nanos\":" + latency.p95()
                    + ",\"ackScheduledOriginP99Nanos\":" + latency.p99()
                    + ",\"groupsCommitted\":" + wal.groupsCommitted()
                    + ",\"maximumBatchSize\":" + wal.maximumBatchSize()
                    + ",\"batchWaitNanos\":" + wal.batchWaitNanos()
                    + ",\"writeNanos\":" + wal.writeNanos()
                    + ",\"forceNanos\":" + wal.forceNanos()
                    + ",\"bytesAppended\":" + wal.bytesAppended()
                    + ",\"forceCalls\":" + forceCalls
                    + ",\"heapGrowthBytes\":" + heapGrowthBytes
                    + ",\"submissionThreadAllocatedBytes\":" + submissionThreadAllocatedBytes
                    + ",\"gcCollections\":" + gcCollections
                    + ",\"gcTimeMillis\":" + gcTimeMillis + "}";
        }
    }

    private record WalMetrics(long groupsCommitted, long maximumBatchSize,
            long batchWaitNanos, long writeNanos, long forceNanos, long bytesAppended) {
        private static WalMetrics between(SigningActiveWal.Snapshot before,
                SigningActiveWal.Snapshot after) {
            return new WalMetrics(after.groupsCommitted() - before.groupsCommitted(),
                    after.maximumBatchSize(), after.batchWaitNanos() - before.batchWaitNanos(),
                    after.writeNanos() - before.writeNanos(),
                    after.forceNanos() - before.forceNanos(),
                    after.bytesAppended() - before.bytesAppended());
        }
    }

    private record Observation(long scheduledNanos,
            SigningActiveWal.Acknowledgement acknowledgement) {
    }

    /* default */ record LatencySummary(long p50, long p95, long p99) {
    }

    private static final class Latencies {
        private final long[] values;
        private int size;

        private Latencies(int capacity) {
            values = new long[capacity];
        }

        private void add(long value) {
            if (size < values.length) {
                values[size++] = value;
            }
        }

        private LatencySummary summary() {
            long[] sorted = Arrays.copyOf(values, size);
            Arrays.sort(sorted);
            return new LatencySummary(percentile(sorted, 0.50), percentile(sorted, 0.95),
                    percentile(sorted, 0.99));
        }

        private static long percentile(long[] sorted, double percentile) {
            if (sorted.length == 0) {
                return 0L;
            }
            int index = Math.min(sorted.length - 1,
                    (int) Math.ceil(percentile * sorted.length) - 1);
            return sorted[index];
        }
    }

    private static final class BenchmarkOperations implements SigningActiveWal.Operations {
        private final boolean fakeForce;
        private long forceCalls;

        private BenchmarkOperations(boolean fakeForce) {
            this.fakeForce = fakeForce;
        }

        @Override public boolean exists(Path path) { return Files.exists(path, LinkOption.NOFOLLOW_LINKS); }
        @Override public boolean isRegularFile(Path path) {
            return Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS);
        }
        @Override public SigningActiveWal.WalChannel createNew(Path path) throws IOException {
            return new BenchmarkChannel(FileChannel.open(path, Set.<OpenOption>of(
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.READ,
                    StandardOpenOption.WRITE)), this);
        }
        @Override public SigningActiveWal.WalChannel openExisting(Path path) throws IOException {
            return new BenchmarkChannel(FileChannel.open(path, StandardOpenOption.READ,
                    StandardOpenOption.WRITE), this);
        }
        @Override public void forceDirectory(Path directory) throws IOException {
            forceCalls++;
            if (!fakeForce) {
                try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
                    channel.force(true);
                }
            }
        }
    }

    private static final class BenchmarkChannel implements SigningActiveWal.WalChannel {
        private final FileChannel channel;
        private final BenchmarkOperations operations;
        private BenchmarkChannel(FileChannel channel, BenchmarkOperations operations) {
            this.channel = channel;
            this.operations = operations;
        }
        @Override public int read(ByteBuffer target) throws IOException { return channel.read(target); }
        @Override public int write(ByteBuffer source) throws IOException { return channel.write(source); }
        @Override public long position() throws IOException { return channel.position(); }
        @Override public SigningActiveWal.WalChannel position(long position) throws IOException {
            channel.position(position);
            return this;
        }
        @Override public long size() throws IOException { return channel.size(); }
        @Override public SigningActiveWal.WalChannel truncate(long size) throws IOException {
            channel.truncate(size);
            return this;
        }
        @Override public boolean isOpen() { return channel.isOpen(); }
        @Override public void close() throws IOException { channel.close(); }
        @Override public void force(boolean metadata) throws IOException {
            operations.forceCalls++;
            if (!operations.fakeForce) {
                channel.force(metadata);
            }
        }
    }
}
