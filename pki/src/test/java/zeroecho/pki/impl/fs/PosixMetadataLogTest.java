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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataStoreException;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.MetadataTransactionId;

final class PosixMetadataLogTest {

    private static final MetadataStoreId STORE_ID =
            new MetadataStoreId("00112233445566778899aabbccddeeff");

    @TempDir
    Path temporaryDirectory;

    @Test
    void createReopenAndExclusiveWriterLifecycleAreStrict() throws IOException {
        System.out.print("createReopenAndExclusiveWriterLifecycleAreStrict ");
        Path path = temporaryDirectory.resolve("lifecycle.log");
        PosixMetadataLog created = PosixMetadataLog.create(path, STORE_ID, supportedProfile(),
                PosixMetadataLog.FaultInjector.NONE);
        assertEquals(STORE_ID, created.storeId());
        assertThrows(MetadataStoreException.class,
                () -> PosixMetadataLog.open(path, supportedProfile(), PosixMetadataLog.FaultInjector.NONE));
        created.close();
        created.close();
        assertThrows(IllegalStateException.class, created::scan);
        try (PosixMetadataLog reopened = PosixMetadataLog.open(
                path, supportedProfile(), PosixMetadataLog.FaultInjector.NONE)) {
            assertEquals(STORE_ID, reopened.storeId());
            assertEquals(PosixMetadataLogScanner.Tail.CLEAN_END, reopened.scan().tail());
            assertEquals(1L, reopened.scan().recoveryEpoch());
        }
        try (PosixMetadataLog reopened = PosixMetadataLog.open(
                path, supportedProfile(), PosixMetadataLog.FaultInjector.NONE)) {
            assertEquals(STORE_ID, reopened.storeId());
            assertEquals(2L, reopened.scan().recoveryEpoch());
        }
        System.out.println("...ok");
    }

    @Test
    void capabilityLimitationsIncludingDirectoryIOExceptionEmitOneSafeWarning() throws IOException {
        System.out.print("capabilityLimitationsIncludingDirectoryIOExceptionEmitOneSafeWarning ");
        Path path = temporaryDirectory.resolve("advisory.log");
        Logger logger = Logger.getLogger(PosixMetadataLog.class.getName());
        AtomicInteger warnings = new AtomicInteger();
        Handler handler = new Handler() {
            @Override
            public void publish(LogRecord record) {
                if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                    assertEquals(
                            "POSIX metadata-log durability capabilities are limited; "
                                    + "continuing in documented best-effort mode",
                            record.getMessage());
                    assertEquals(0, record.getParameters() == null ? 0 : record.getParameters().length);
                    assertEquals(null, record.getThrown());
                    warnings.incrementAndGet();
                }
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };
        logger.addHandler(handler);
        try {
            PosixMetadataLog.CapabilityProfile limited = new PosixMetadataLog.CapabilityProfile() {
                @Override
                public boolean posixAvailable(Path parent) {
                    return false;
                }

                @Override
                public boolean localFileSystem(Path parent) {
                    return false;
                }

                @Override
                public void forceParent(FileChannel parentDirectory) throws IOException {
                    throw new IOException("injected");
                }
            };
            try (PosixMetadataLog log = PosixMetadataLog.create(
                    path, STORE_ID, limited, PosixMetadataLog.FaultInjector.NONE)) {
                assertEquals(STORE_ID, log.storeId());
            }
            assertEquals(1, warnings.get());
        } finally {
            logger.removeHandler(handler);
        }
        System.out.println("...ok");
    }

    @Test
    void terminalizedTransactionStateIsBoundedBySimultaneousActivity() throws IOException {
        System.out.print("terminalizedTransactionStateIsBoundedBySimultaneousActivity ");
        PosixMetadataLogScanner.TransactionCounter counter =
                PosixMetadataLogScanner.TransactionCounter.first();
        MetadataTransactionId counterValue = null;
        for (int index = 0; index < 100_000; index++) {
            counterValue = counter.issue(STORE_ID);
        }
        assertEquals("000000000000000000000000000186a0", counterValue.token());
        PosixMetadataLogScanner.TransactionCounter carry =
                PosixMetadataLogScanner.TransactionCounter.startingAt(0L, -1L);
        assertEquals("0000000000000000ffffffffffffffff", carry.issue(STORE_ID).token());
        assertEquals("00000000000000010000000000000000", carry.issue(STORE_ID).token());
        PosixMetadataLogScanner.TransactionCounter maximum =
                PosixMetadataLogScanner.TransactionCounter.startingAt(-1L, -1L);
        assertEquals("ffffffffffffffffffffffffffffffff", maximum.issue(STORE_ID).token());
        assertThrows(IllegalStateException.class, () -> maximum.issue(STORE_ID));
        assertThrows(IllegalArgumentException.class,
                () -> PosixMetadataLogScanner.TransactionCounter.startingAt(0L, 0L));

        Path path = temporaryDirectory.resolve("bounded-active.log");
        try (PosixMetadataLog log = PosixMetadataLog.create(
                path, STORE_ID, supportedProfile(), PosixMetadataLog.FaultInjector.NONE)) {
            for (int index = 0; index < 128; index++) {
                MetadataTransactionId transactionId = log.issue();
                log.commit(transactionId, index);
                assertEquals(0, log.activeTransactionCount());
            }
            MetadataTransactionId first = log.issue();
            MetadataTransactionId second = log.issue();
            assertEquals(2, log.activeTransactionCount());
            log.reject(first, 1);
            assertEquals(1, log.activeTransactionCount());
            log.commit(second, 10_002L);
            assertEquals(0, log.activeTransactionCount());
        }
        System.out.println("...ok");
    }

    @Test
    void issuanceMutationsAndEmptyTerminalOutcomesRecoverExactly() throws IOException {
        System.out.print("issuanceMutationsAndEmptyTerminalOutcomesRecoverExactly ");
        Path path = temporaryDirectory.resolve("transactions.log");
        MetadataTransactionId committed;
        MetadataTransactionId rejected;
        try (PosixMetadataLog log = PosixMetadataLog.create(
                path, STORE_ID, supportedProfile(), PosixMetadataLog.FaultInjector.NONE)) {
            committed = log.issue();
            try (GeneratedContent content = new GeneratedContent(40_000)) {
                assertEquals(1L, log.appendMutation(
                        committed, MetadataFrameCodec.FrameType.MUTATION_CREATE,
                        40_000L, content, CancellationSignal.NONE).sequence());
                assertTrue(content.closedStream);
            }
            PosixMetadataLogScanner.Terminal committedResult = log.commit(committed, 9L);
            assertEquals(PosixMetadataLogScanner.TerminalKind.COMMITTED, committedResult.kind());
            assertThrows(IllegalArgumentException.class, () -> log.commit(committed, 10L));
            rejected = log.issue();
            PosixMetadataLogScanner.Terminal rejectedResult = log.reject(rejected, 47);
            assertEquals(47, rejectedResult.failureCode().orElseThrow());
        }
        try (PosixMetadataLog reopened = PosixMetadataLog.open(
                path, supportedProfile(), PosixMetadataLog.FaultInjector.NONE)) {
            MetadataTransactionId continued = reopened.issue();
            assertEquals("00000000000000000000000000000003", continued.token());
            reopened.reject(continued, 48);
            PosixMetadataLogScanner.RecoveryResult recovered = reopened.scan();
            assertEquals(1L, recovered.transactions().get(committed).mutationCount());
            assertEquals(9L, recovered.transactions().get(committed).terminal()
                    .orElseThrow().committedRevision().orElseThrow());
            assertEquals(0L, recovered.transactions().get(rejected).mutationCount());
            assertEquals(47, recovered.transactions().get(rejected).terminal()
                    .orElseThrow().failureCode().orElseThrow());
            assertEquals(48, recovered.transactions().get(continued).terminal()
                    .orElseThrow().failureCode().orElseThrow());
        }
        System.out.println("...ok");
    }

    @Test
    void issuanceAndMutationAppendFaultsRequireRecoveryWithoutInventingOutcomes() throws IOException {
        System.out.print("issuanceAndMutationAppendFaultsRequireRecoveryWithoutInventingOutcomes ");
        Path issuancePath = temporaryDirectory.resolve("issuance-fault.log");
        PosixMetadataLog.FaultInjector issuanceFault = point -> {
            if (point == PosixMetadataLog.FaultPoint.ISSUANCE_APPEND) {
                throw new IOException("injected");
            }
        };
        try (PosixMetadataLog log = PosixMetadataLog.create(
                issuancePath, STORE_ID, supportedProfile(), issuanceFault)) {
            assertThrows(IOException.class, log::issue);
            assertEquals(0, log.activeTransactionCount());
            assertThrows(IOException.class, log::issue);
        }
        assertTrue(scan(issuancePath).transactions().isEmpty());
        try (PosixMetadataLog reopened = PosixMetadataLog.open(
                issuancePath, supportedProfile(), PosixMetadataLog.FaultInjector.NONE)) {
            MetadataTransactionId first = reopened.issue();
            assertEquals("00000000000000000000000000000001", first.token());
            reopened.reject(first, 1);
        }

        Path uncertainPath = temporaryDirectory.resolve("issuance-force-uncertain.log");
        AtomicInteger issuanceForceCount = new AtomicInteger();
        PosixMetadataLog.FaultInjector issuanceForceFault = point -> {
            if (point == PosixMetadataLog.FaultPoint.FILE_FORCE
                    && issuanceForceCount.incrementAndGet() == 2) {
                throw new IOException("injected");
            }
        };
        try (PosixMetadataLog log = PosixMetadataLog.create(
                uncertainPath, STORE_ID, supportedProfile(), issuanceForceFault)) {
            assertThrows(IOException.class, log::issue);
            assertThrows(IOException.class, log::issue);
        }
        PosixMetadataLogScanner.RecoveryResult uncertainRecovery = scan(uncertainPath);
        assertTrue(uncertainRecovery.transactions().containsKey(
                new MetadataTransactionId(STORE_ID, "00000000000000000000000000000001")));
        try (PosixMetadataLog reopened = PosixMetadataLog.open(
                uncertainPath, supportedProfile(), PosixMetadataLog.FaultInjector.NONE)) {
            assertEquals("00000000000000000000000000000002", reopened.issue().token());
        }

        Path path = temporaryDirectory.resolve("append-fault.log");
        AtomicInteger mutationFault = new AtomicInteger(1);
        PosixMetadataLog.FaultInjector faults = point -> {
            if (point == PosixMetadataLog.FaultPoint.MUTATION_APPEND
                    && mutationFault.getAndDecrement() > 0) {
                throw new IOException("injected");
            }
        };
        try (PosixMetadataLog log = PosixMetadataLog.create(path, STORE_ID, supportedProfile(), faults)) {
            MetadataTransactionId transactionId = log.issue();
            try (ImmutableByteContent content = new ImmutableByteContent(new byte[] { 1 })) {
                assertThrows(IOException.class, () -> log.appendMutation(
                        transactionId, MetadataFrameCodec.FrameType.MUTATION_CREATE,
                        1L, content, CancellationSignal.NONE));
            }
            assertThrows(IOException.class, log::issue);
        }
        PosixMetadataLogScanner.RecoveryResult recovered = scan(path);
        assertEquals(1, recovered.transactions().size());
        assertTrue(recovered.transactions().values().iterator().next().terminal().isEmpty());
        System.out.println("...ok");
    }

    @Test
    void terminalForceAndPostForceUncertaintyResolveOnlyByScanning() throws IOException {
        System.out.print("terminalForceAndPostForceUncertaintyResolveOnlyByScanning ");
        Path appendPath = temporaryDirectory.resolve("terminal-append.log");
        MetadataTransactionId appendId;
        PosixMetadataLog.FaultInjector appendFault = point -> {
            if (point == PosixMetadataLog.FaultPoint.TERMINAL_APPEND) {
                throw new IOException("injected");
            }
        };
        try (PosixMetadataLog log = PosixMetadataLog.create(
                appendPath, STORE_ID, supportedProfile(), appendFault)) {
            appendId = log.issue();
            assertThrows(PosixMetadataLog.OutcomeUnknownException.class, () -> log.commit(appendId, 3L));
            assertEquals(1, log.activeTransactionCount());
            assertThrows(IOException.class, log::issue);
        }
        assertTrue(scan(appendPath).transactions().get(appendId).terminal().isEmpty());

        Path forcePath = temporaryDirectory.resolve("terminal-force.log");
        MetadataTransactionId forceId;
        AtomicInteger forceCount = new AtomicInteger();
        PosixMetadataLog.FaultInjector forceFault = point -> {
            if (point == PosixMetadataLog.FaultPoint.FILE_FORCE
                    && forceCount.incrementAndGet() == 3) {
                throw new IOException("injected");
            }
        };
        try (PosixMetadataLog log = PosixMetadataLog.create(
                forcePath, STORE_ID, supportedProfile(), forceFault)) {
            forceId = log.issue();
            assertThrows(PosixMetadataLog.OutcomeUnknownException.class, () -> log.commit(forceId, 4L));
        }
        assertEquals(PosixMetadataLogScanner.TerminalKind.COMMITTED,
                scan(forcePath).transactions().get(forceId).terminal().orElseThrow().kind());

        Path hiddenPath = temporaryDirectory.resolve("post-force.log");
        MetadataTransactionId hiddenId;
        PosixMetadataLog.FaultInjector hiddenFault = point -> {
            if (point == PosixMetadataLog.FaultPoint.POST_FORCE_UNCERTAINTY) {
                throw new IOException("injected");
            }
        };
        try (PosixMetadataLog log = PosixMetadataLog.create(
                hiddenPath, STORE_ID, supportedProfile(), hiddenFault)) {
            hiddenId = log.issue();
            assertThrows(PosixMetadataLog.OutcomeUnknownException.class, () -> log.reject(hiddenId, 8));
        }
        assertEquals(8, scan(hiddenPath).transactions().get(hiddenId).terminal()
                .orElseThrow().failureCode().orElseThrow());
        System.out.println("...ok");
    }

    private static PosixMetadataLog.CapabilityProfile supportedProfile() {
        return new PosixMetadataLog.CapabilityProfile() {
            @Override
            public boolean posixAvailable(Path parent) {
                return true;
            }

            @Override
            public boolean localFileSystem(Path parent) {
                return true;
            }

            @Override
            public void forceParent(FileChannel parentDirectory) throws IOException {
                parentDirectory.force(true);
            }
        };
    }

    private static PosixMetadataLogScanner.RecoveryResult scan(Path path) throws IOException {
        try (FileChannel channel = FileChannel.open(path, java.nio.file.StandardOpenOption.READ)) {
            return PosixMetadataLogScanner.scan(channel);
        }
    }

    private static final class GeneratedContent implements RepeatableContent {
        private final int length;
        private boolean closedStream;

        private GeneratedContent(int length) {
            this.length = length;
        }

        @Override
        public InputStream openStream() {
            return new ByteArrayInputStream(new byte[length]) {
                @Override
                public void close() throws IOException {
                    closedStream = true;
                    super.close();
                }
            };
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.empty();
        }

        @Override
        public String contentId() {
            return "generated:test";
        }

        @Override
        public void close() {
        }
    }
}
