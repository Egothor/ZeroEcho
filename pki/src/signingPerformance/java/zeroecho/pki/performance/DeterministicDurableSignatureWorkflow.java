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
package zeroecho.pki.performance;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.LockSupport;

import zeroecho.pki.api.EncodedObject;
import zeroecho.pki.api.Encoding;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.spi.crypto.SignatureWorkflow;

/**
 * Benchmark-only local provider with deterministic delay and observable durable
 * intent/result writes.
 */
@SuppressWarnings({ "PMD.CommentDefaultAccessModifier", "PMD.DoNotUseThreads", "PMD.CommentRequired",
        "PMD.AvoidUsingVolatile" })
final class DeterministicDurableSignatureWorkflow implements SignatureWorkflow {

    static final String ID = "signing-performance-provider";
    static final String ALGORITHM = "SHA256withRSA";
    private static final ConfigurationCommitment CONFIGURATION_COMMITMENT = new ConfigurationCommitment(
            java.util.HexFormat.of().parseHex("9f59d08a9f36ae0d87a2c20df2f78ef863a39af07273d5d26c2290469895ac14"));

    private final Path operationRoot;
    private final int meanMillis;
    private final int jitterMillis;
    private final long seed;
    private final AtomicLong submissionSequence = new AtomicLong();
    private final ConcurrentMap<PkiId, StoredOperation> operations = new ConcurrentHashMap<>();
    private final LongAdder providerNanos = new LongAdder();
    private final LongAdder providerCalls = new LongAdder();
    private final LongAdder statusNanos = new LongAdder();
    private final LongAdder statusCalls = new LongAdder();
    private final LongAdder forceCount = new LongAdder();
    private final LongAdder writeCount = new LongAdder();
    private final LongAdder writeBytes = new LongAdder();
    private final BoundedLatencySamples forceLatencies;

    DeterministicDurableSignatureWorkflow(Path operationRoot, int meanMillis, int jitterMillis, long seed,
            int sampleCapacity) {
        this.operationRoot = Objects.requireNonNull(operationRoot, "operationRoot").toAbsolutePath().normalize();
        if (meanMillis < 0 || jitterMillis < 0 || jitterMillis > meanMillis) {
            throw new IllegalArgumentException("invalid provider delay distribution");
        }
        this.meanMillis = meanMillis;
        this.jitterMillis = jitterMillis;
        this.seed = seed;
        this.forceLatencies = new BoundedLatencySamples(sampleCapacity, seed ^ 0x61c8_8646_80b5_83ebL);
        try {
            Files.createDirectories(this.operationRoot);
        } catch (IOException failure) {
            throw new IllegalStateException("cannot create benchmark provider root", failure);
        }
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public ConfigurationCommitment configurationCommitment() {
        return CONFIGURATION_COMMITMENT;
    }

    @Override
    public void validateSigningDomain(String namespace, Duration horizon, Duration permittedSkew) {
        Objects.requireNonNull(namespace, "namespace");
        Objects.requireNonNull(horizon, "horizon");
        Objects.requireNonNull(permittedSkew, "permittedSkew");
        if (!namespace.endsWith("." + ID) || !Duration.ofDays(90).equals(horizon)
                || !Duration.ZERO.equals(permittedSkew)) {
            throw new IllegalArgumentException("benchmark provider signing domain mismatch");
        }
    }

    @Override
    public PkiId submitSign(SignRequest request, CallControl control) {
        Objects.requireNonNull(request, "request");
        Objects.requireNonNull(control, "control").requireActive(Instant.now());
        long started = System.nanoTime();
        providerCalls.increment();
        try {
            StoredOperation existing = operations.get(request.submissionId());
            if (existing != null) {
                validateReplay(request, existing);
                return request.submissionId();
            }
            StoredOperation created = new StoredOperation(request.semanticFingerprint(), request.fencingToken(),
                    running());
            StoredOperation raced = operations.putIfAbsent(request.submissionId(), created);
            if (raced != null) {
                validateReplay(request, raced);
                return request.submissionId();
            }

            Path prefix = operationRoot.resolve(fileName(request.submissionId()));
            persistNew(prefix.resolveSibling(prefix.getFileName() + ".intent"),
                    request.semanticFingerprint().getBytes(StandardCharsets.US_ASCII));
            delay(submissionSequence.getAndIncrement());
            control.requireActive(Instant.now());
            byte[] signature = signature(request);
            persistNew(prefix.resolveSibling(prefix.getFileName() + ".result"), signature);
            OperationStatus terminal = new OperationStatus(State.SUCCEEDED, Instant.now(), Optional.of("SIGNED"),
                    Optional.of(new OperationResult(Optional.of(new EncodedObject(Encoding.BINARY, signature)),
                            Optional.empty())));
            created.status = terminal;
            return request.submissionId();
        } finally {
            providerNanos.add(System.nanoTime() - started);
        }
    }

    @Override
    public PkiId submitVerify(VerifyRequest request, CallControl control) {
        throw new UnsupportedOperationException("benchmark provider does not verify");
    }

    @Override
    public OperationStatus status(PkiId operationId, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(control, "control").requireActive(Instant.now());
        long started = System.nanoTime();
        statusCalls.increment();
        try {
            StoredOperation operation = operations.get(operationId);
            if (operation == null) {
                return new OperationStatus(State.FAILED, Instant.EPOCH, Optional.of("UNKNOWN_OPERATION"),
                        Optional.empty());
            }
            return operation.status;
        } finally {
            statusNanos.add(System.nanoTime() - started);
        }
    }

    @Override
    public boolean cancel(PkiId operationId, long fencingToken, String reason, CallControl control) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(reason, "reason");
        return false;
    }

    @Override
    public Registration register(NotificationSink sink) {
        Objects.requireNonNull(sink, "sink");
        return () -> {
            // This synchronous benchmark provider emits no advisory callbacks.
        };
    }

    @Override
    public Set<String> supportedAlgorithms() {
        return Set.of(ALGORITHM);
    }

    @Override
    public void close() {
        operations.clear();
    }

    Metrics metrics() {
        return new Metrics(providerCalls.sum(), providerNanos.sum(), statusCalls.sum(), statusNanos.sum(),
                forceCount.sum(), writeCount.sum(), writeBytes.sum(), operations.size(), forceLatencies.summarize());
    }

    void retire(PkiId operationId) {
        StoredOperation operation = operations.get(Objects.requireNonNull(operationId, "operationId"));
        if (operation == null || !operation.status.isTerminal()) {
            throw new IllegalStateException("benchmark provider operation is not terminal");
        }
        if (!operations.remove(operationId, operation)) {
            throw new IllegalStateException("benchmark provider operation retirement raced");
        }
        Path prefix = operationRoot.resolve(fileName(operationId));
        try {
            Files.deleteIfExists(prefix.resolveSibling(prefix.getFileName() + ".intent"));
            Files.deleteIfExists(prefix.resolveSibling(prefix.getFileName() + ".result"));
        } catch (IOException failure) {
            throw new IllegalStateException("benchmark provider retirement failed", failure);
        }
    }

    void retireTerminalOperations() {
        for (PkiId operationId : Set.copyOf(operations.keySet())) {
            retire(operationId);
        }
    }

    void resetMetrics() {
        submissionSequence.set(0L);
        providerNanos.reset();
        providerCalls.reset();
        statusNanos.reset();
        statusCalls.reset();
        forceCount.reset();
        writeCount.reset();
        writeBytes.reset();
        forceLatencies.reset();
    }

    private void validateReplay(SignRequest request, StoredOperation operation) {
        if (!MessageDigest.isEqual(request.semanticFingerprint().getBytes(StandardCharsets.US_ASCII),
                operation.fingerprint.getBytes(StandardCharsets.US_ASCII))
                || request.fencingToken() < operation.fence) {
            throw new IllegalStateException("conflicting benchmark signing replay");
        }
    }

    private void persistNew(Path target, byte[] bytes) {
        try (FileChannel channel = FileChannel.open(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) {
                channel.write(buffer);
            }
            writeCount.increment();
            writeBytes.add(bytes.length);
            force(channel);
        } catch (IOException failure) {
            throw new IllegalStateException("benchmark provider durability failed", failure);
        }
        try (FileChannel directory = FileChannel.open(operationRoot, StandardOpenOption.READ)) {
            force(directory);
        } catch (IOException failure) {
            throw new IllegalStateException("benchmark provider directory durability failed", failure);
        }
    }

    private void force(FileChannel channel) throws IOException {
        long started = System.nanoTime();
        channel.force(true);
        forceLatencies.add(System.nanoTime() - started);
        forceCount.increment();
    }

    private void delay(long sequence) {
        int offset = 0;
        if (jitterMillis != 0) {
            long width = Math.addExact(Math.multiplyExact((long) jitterMillis, 2L), 1L);
            offset = (int) Long.remainderUnsigned(mix64(seed ^ sequence), width) - jitterMillis;
        }
        long remaining = Duration.ofMillis(meanMillis + offset).toNanos();
        long deadline = System.nanoTime() + remaining;
        while (remaining > 0L) {
            LockSupport.parkNanos(remaining);
            if (Thread.currentThread().isInterrupted()) {
                throw new IllegalStateException("benchmark provider interrupted");
            }
            remaining = deadline - System.nanoTime();
        }
    }

    private static byte[] signature(SignRequest request) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            try (InputStream input = request.content().openStream()) {
                byte[] buffer = new byte[8_192];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (count != 0) {
                        digest.update(buffer, 0, count);
                    }
                }
            }
            byte[] hash = digest.digest();
            byte[] signature = new byte[256];
            for (int offset = 0; offset < signature.length; offset += hash.length) {
                System.arraycopy(hash, 0, signature, offset, Math.min(hash.length, signature.length - offset));
            }
            Arrays.fill(hash, (byte) 0);
            return signature;
        } catch (IOException | NoSuchAlgorithmException failure) {
            throw new IllegalStateException("benchmark provider signing failed", failure);
        }
    }

    private static String fileName(PkiId operationId) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(operationId.value().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException failure) {
            throw new IllegalStateException("SHA-256 is unavailable", failure);
        }
    }

    private static OperationStatus running() {
        return new OperationStatus(State.RUNNING, Instant.now(), Optional.of("RUNNING"), Optional.empty());
    }

    private static long mix64(long value) {
        long mixed = value;
        mixed = (mixed ^ (mixed >>> 30)) * 0xbf58_476d_1ce4_e5b9L;
        mixed = (mixed ^ (mixed >>> 27)) * 0x94d0_49bb_1331_11ebL;
        return mixed ^ (mixed >>> 31);
    }

    private static final class StoredOperation {
        private final String fingerprint;
        private final long fence;
        private volatile OperationStatus status;

        private StoredOperation(String fingerprint, long fence, OperationStatus status) {
            this.fingerprint = fingerprint;
            this.fence = fence;
            this.status = status;
        }
    }

    record Metrics(long providerCalls, long providerNanos, long statusCalls, long statusNanos, long forceCount,
            long writeCount, long writeBytes, int retainedOperations, BoundedLatencySamples.Summary forceLatency) {
    }
}
