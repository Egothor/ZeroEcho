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

package zeroecho.pki.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedWriter;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.GarbageCollectorMXBean;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.api.signing.SemanticSigningState;
import zeroecho.pki.api.signing.SemanticSigningOperation;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.LocalSigningConfiguration;
import zeroecho.pki.application.LocalPkiSessionConfiguration;
import zeroecho.pki.application.LocalSigningResult;
import zeroecho.pki.application.PkiSession;
import zeroecho.pki.application.PkiSessionConfiguration;

/** Informational, serial root-publication measurements; no throughput or latency acceptance threshold. */
@Tag("local-performance")
public class PkiLocalPerformanceTest {
    private static final int WARMUP = 5;
    private static final int MEASURED = 30;

    @Test
    @Timeout(1800)
    void recordThreeFreshJvmRepetitionsAndPackagedStartup() throws Exception {
        Path root = PkiLocalGateFixture.privateDirectory(Path.of(System.getProperty("pki.validation.output")), "measurement-");
        for (int repetition = 0; repetition < 3; repetition++) {
            Path directory = PkiLocalGateFixture.privateDirectory(root, "rep-" + repetition + "-");
            PkiLocalGateFixture.ProcessResult result = PkiLocalGateFixture.child(getClass(), directory, "measurement", directory.toString(),
                    System.getProperty("pki.validation.executable"), Integer.toString(repetition));
            assertEquals(0, result.exit(), result.errors());
            assertTrue(Files.size(directory.resolve("samples.csv")) > 0);
        }
    }

    /** One isolated repetition: same generated RSA key, separate local and reactive stores. */
    public static void main(String[] arguments) throws Exception {
        Path directory = Path.of(arguments[0]);
        Path executable = Path.of(arguments[1]);
        int repetition = Integer.parseInt(arguments[2]);
        KeyPair pair = PkiLocalGateFixture.rsaKey();
        Files.writeString(directory.resolve("environment.txt"), environment(repetition));
        try (BufferedWriter samples = Files.newBufferedWriter(directory.resolve("samples.csv"))) {
            samples.write("mode,phase,sample,nanoseconds,polls\n");
            // Alternate order to expose, rather than silently hide, within-JVM ordering effects.
            List<String> modes = repetition % 2 == 0 ? List.of("local", "reactor") : List.of("reactor", "local");
            for (String mode : modes) {
                Path configuration = PkiLocalGateFixture.configuration(directory.resolve(mode), pair);
                measureMode(mode, configuration, samples, directory);
            }
            Path startup = PkiLocalGateFixture.configuration(directory.resolve("startup"), pair);
            for (int index = -WARMUP; index < MEASURED; index++) {
                PkiLocalGateFixture.ProcessResult result = PkiLocalGateFixture.cli(executable, startup, directory, "startup-" + (index + WARMUP),
                        "configuration.validate");
                assertEquals(0, result.exit(), result.output());
                sample(samples, "packaged-startup", index, result.elapsedNanos(), 0);
            }
        }
    }

    private static void measureMode(String mode, Path file, BufferedWriter samples, Path output) throws Exception {
        LocalPkiSessionConfiguration local = null;
        for (int index = -WARMUP; index < MEASURED; index++) {
            long started = System.nanoTime();
            local = PkiCliConfiguration.read(file);
            sample(samples, mode + "-configuration-parse", index, System.nanoTime() - started, 0);
        }
        long started = System.nanoTime();
        PkiSession session = mode.equals("local")
                ? PkiSession.openLocal(local, PkiLocalGateFixture.dependencies())
                : PkiSession.open(reactorConfiguration(local), PkiLocalGateFixture.dependencies());
        samples.write(mode + ",open,0," + (System.nanoTime() - started) + ",0\n");
        try {
            PkiLocalGateFixture.seedProfile(session);
            Files.writeString(output.resolve(mode + "-resources-before.txt"), resources());
            for (int index = -WARMUP; index < MEASURED; index++) {
                started = System.nanoTime();
                int polls = mode.equals("local") ? localOperation(session, index) : reactorOperation(session, index);
                sample(samples, mode, index, System.nanoTime() - started, polls);
            }
            Files.writeString(output.resolve(mode + "-resources-after.txt"), resources());
        } finally {
            started = System.nanoTime();
            session.close();
            samples.write(mode + ",close,0," + (System.nanoTime() - started) + ",0\n");
            samples.flush();
        }
    }

    private static int localOperation(PkiSession session, int index) {
        LocalSigningResult.Completed completed = assertInstanceOf(LocalSigningResult.Completed.class, session.localSigning().orElseThrow()
                .execute(PkiLocalGateFixture.rootOperation("Signing Measurement Sample " + (index + WARMUP)), CancellationSignal.NONE));
        assertTrue(completed.result().fields().containsKey("credentialId"));
        return 0;
    }

    private static int reactorOperation(PkiSession session, int index) throws Exception {
        PkiId id = PkiLocalGateFixture.accept(session, "Signing Measurement Sample " + (index + WARMUP));
        long deadline = System.nanoTime() + Duration.ofSeconds(90).toNanos();
        int polls = 0;
        while (true) {
            SemanticSigningOperation observed = session.semanticSigning().orElseThrow().find(id).orElseThrow();
            polls++;
            if (observed.state() == SemanticSigningState.COMPLETED) {
                assertTrue(session.signingCommands().orElseThrow().completedResult(observed).fields().containsKey("credentialId"));
                return polls;
            }
            assertTrue(observed.state() == SemanticSigningState.SIGNING || observed.state() == SemanticSigningState.PUBLISHING,
                    "Reactive publication failed: " + observed.state());
            // Failure guard only; there is no numerical performance gate.
            assertTrue(System.nanoTime() < deadline, "Reactive operation did not finish within the test failure guard");
            Thread.sleep(1);
        }
    }

    private static PkiSessionConfiguration reactorConfiguration(LocalPkiSessionConfiguration local) {
        LocalSigningConfiguration signing = local.signing().orElseThrow();
        PkiSessionConfiguration.SigningTopology topology = new PkiSessionConfiguration.SigningTopology(new PkiSessionConfiguration.SigningCoordinatorLimits(
                1, PkiLocalGateFixture.CLAIM_LEASE, PkiLocalGateFixture.CALL_TIMEOUT, Duration.ofMillis(10), Duration.ofSeconds(5)),
                List.of(), new PkiSessionConfiguration.SigningLanePool(1, 1));
        return new PkiSessionConfiguration(PkiSessionConfiguration.CURRENT_VERSION, local.store(), local.audit(),
                Optional.of(new PkiSessionConfiguration.SigningConfiguration(signing.provider(), signing.signatureAlgorithm(),
                        signing.signingTtl(), signing.unlockEnvironmentVariable(), topology, signing.pureEdDsaMaximumTbsBytes())),
                local.publishers(), local.bindingProviders());
    }

    private static void sample(BufferedWriter writer, String mode, int index, long nanos, int polls) throws Exception {
        writer.write(mode + "," + (index < 0 ? "warmup" : "measured") + "," + index + "," + nanos + "," + polls + "\n");
        writer.flush();
    }

    private static String environment(int repetition) throws Exception {
        String cpu = "unavailable";
        Path cpuInfo = Path.of("/proc/cpuinfo");
        if (Files.isReadable(cpuInfo)) {
            try (Stream<String> lines = Files.lines(cpuInfo)) {
                cpu = lines.filter(line -> line.startsWith("model name")).findFirst().orElse("unavailable");
            }
        }
        return "timestamp=" + Instant.now() + "\nrepetition=" + repetition + "\njava=" + System.getProperty("java.runtime.version")
                + "\nvm=" + System.getProperty("java.vm.name") + "\nos=" + System.getProperty("os.name")
                + "\nosVersion=" + System.getProperty("os.version") + "\narchitecture=" + System.getProperty("os.arch")
                + "\navailableProcessors=" + Runtime.getRuntime().availableProcessors() + "\ncpu=" + cpu
                + "\nmaxHeap=" + Runtime.getRuntime().maxMemory() + "\nchildHeap=-Xms128m -Xmx512m"
                + "\nsigning=RSA2048 SHA256withRSA\nwarmup=5\nmeasured=30\nconcurrency=1"
                + "\nclaimLease=PT10S\nproviderTimeout=PT5S\nreactorIdlePoll=PT0.01S\nobservationPoll=PT0.001S"
                + "\nstore=" + cpuInfo.getFileSystem().provider().getScheme() + " (local fs provider; test output path identifies actual mount)"
                + "\naudit=memory size128\n";
    }

    private static String resources() {
        StringBuilder result = new StringBuilder();
        MemoryMXBean memory = ManagementFactory.getMemoryMXBean();
        result.append("heapUsed=").append(memory.getHeapMemoryUsage().getUsed()).append('\n');
        result.append("heapCommitted=").append(memory.getHeapMemoryUsage().getCommitted()).append('\n');
        result.append("threadCount=").append(ManagementFactory.getThreadMXBean().getThreadCount()).append('\n');
        for (GarbageCollectorMXBean collector : ManagementFactory.getGarbageCollectorMXBeans()) {
            result.append("gc=").append(collector.getName()).append(" count=").append(collector.getCollectionCount())
                    .append(" milliseconds=").append(collector.getCollectionTime()).append('\n');
        }
        return result.toString();
    }
}
