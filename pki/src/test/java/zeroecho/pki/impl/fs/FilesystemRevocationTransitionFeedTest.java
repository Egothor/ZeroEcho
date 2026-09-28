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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.attr.AttributeId;
import zeroecho.pki.api.attr.AttributeSet;
import zeroecho.pki.api.attr.AttributeValue;
import zeroecho.pki.api.revocation.RevocationState;
import zeroecho.pki.api.revocation.RevocationTransition;
import zeroecho.pki.impl.core.attr.SimpleAttributeSet;
import zeroecho.pki.spi.store.MetadataStoreId;
import zeroecho.pki.spi.store.RevocationTransitionFeed;

final class FilesystemRevocationTransitionFeedTest {
    private static final MetadataStoreId STORE_ID = new MetadataStoreId("102030405060708090a0b0c0d0e0f001");
    private static final MetadataStoreId OTHER_STORE_ID =
            new MetadataStoreId("102030405060708090a0b0c0d0e0f002");
    private static final int LARGE_RECORD_BYTES = 200_000;

    @TempDir Path temporaryDirectory;

    @Test
    void validatesGenesisHeadAndOlderPrefixesAndRejectsFalseCoordinates() throws Exception {
        try (FilesystemRevocationAuthority authority = authority(temporaryDirectory.resolve("prefixes"), STORE_ID, true)) {
            FilesystemRevocationLog.RecoveryTarget genesis = authority.head();
            authority.requirePrefix(watermark(genesis), genesis.boundary(), zeroecho.core.io.CancellationSignal.NONE);
            append(authority, "credential:first", 1);
            FilesystemRevocationLog.RecoveryTarget first = authority.head();
            authority.requirePrefix(watermark(first), first.boundary(), zeroecho.core.io.CancellationSignal.NONE);
            append(authority, "credential:second", 2);
            FilesystemRevocationLog.RecoveryTarget head = authority.head();
            authority.requirePrefix(watermark(genesis), genesis.boundary(), zeroecho.core.io.CancellationSignal.NONE);
            authority.requirePrefix(watermark(first), first.boundary(), zeroecho.core.io.CancellationSignal.NONE);
            authority.requirePrefix(watermark(head), head.boundary(), zeroecho.core.io.CancellationSignal.NONE);
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(
                    new RevocationTransitionFeed.HighWatermark(OTHER_STORE_ID, first.globalRevision(), first.globalCommitment().value()),
                    first.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(
                    new RevocationTransitionFeed.HighWatermark(OTHER_STORE_ID, 0,
                            RevocationTransitionFrameCodec.initialCommitment(OTHER_STORE_ID).value()),
                    genesis.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(
                    new RevocationTransitionFeed.HighWatermark(STORE_ID, 0, "f".repeat(64)),
                    genesis.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(watermark(genesis),
                    genesis.boundary() + 1, zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(
                    new RevocationTransitionFeed.HighWatermark(STORE_ID, head.globalRevision() + 1, head.globalCommitment().value()),
                    head.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(watermark(first),
                    head.boundary() + 1, zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(watermark(head),
                    first.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(
                    new RevocationTransitionFeed.HighWatermark(STORE_ID, head.globalRevision(), "f".repeat(64)),
                    head.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IOException.class, () -> authority.requirePrefix(
                    new RevocationTransitionFeed.HighWatermark(STORE_ID, first.globalRevision(), "f".repeat(64)),
                    first.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(IOException.class, () -> authority.requirePrefix(watermark(first),
                    first.boundary() + 1, zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(NullPointerException.class, () -> authority.requirePrefix(null, 0, zeroecho.core.io.CancellationSignal.NONE));
            assertThrows(NullPointerException.class, () -> authority.requirePrefix(watermark(head), head.boundary(), null));
        }
    }

    @Test
    void prefixValidationReadsExactlyPreambleAndOneSuccessorWithoutScanningHistory() throws Exception {
        Path root = temporaryDirectory.resolve("bounded-prefix");
        FilesystemRevocationLog.RecoveryTarget prefix;
        FilesystemRevocationLog.RecoveryTarget successor;
        try (FilesystemRevocationAuthority authority = authority(root, STORE_ID, true)) {
            for (int index = 0; index < 32; index++) append(authority, "credential:prefix-" + index, index + 1);
            prefix = authority.head();
            append(authority, "credential:large", 33, SimpleAttributeSet.builder()
                    .put(new AttributeId("large"), new AttributeValue.BytesValue(new byte[LARGE_RECORD_BYTES])).build());
            successor = authority.head();
            append(authority, "credential:not-read", 34);
        }
        AtomicLong bytesRead = new AtomicLong();
        List<CountingChannel> channels = new ArrayList<>();
        FilesystemRevocationAuthority.FeedChannelFactory factory = path -> {
            CountingChannel channel = new CountingChannel(FileChannel.open(path, StandardOpenOption.READ), bytesRead);
            channels.add(channel);
            return channel;
        };
        try (FilesystemRevocationAuthority authority = FilesystemRevocationAuthority.open(new FsPaths(root), STORE_ID,
                credentialId -> { }, false, FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE, factory)) {
            long scans = authority.revocationLogScanInvocationCount();
            authority.requirePrefix(watermark(prefix), prefix.boundary(), zeroecho.core.io.CancellationSignal.NONE);
            assertEquals(RevocationTransitionFrameCodec.PREAMBLE_BYTES + successor.boundary() - prefix.boundary(), bytesRead.get());
            assertEquals(1, channels.size());
            assertFalse(channels.getFirst().isOpen());
            bytesRead.set(0);
            FilesystemRevocationLog.RecoveryTarget head = authority.head();
            authority.requirePrefix(watermark(head), head.boundary(), zeroecho.core.io.CancellationSignal.NONE);
            assertEquals(RevocationTransitionFrameCodec.PREAMBLE_BYTES, bytesRead.get());
            assertFalse(channels.getLast().isOpen());
            assertThrows(IOException.class, () -> authority.requirePrefix(
                    new RevocationTransitionFeed.HighWatermark(STORE_ID, prefix.globalRevision(), "f".repeat(64)),
                    prefix.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertFalse(channels.getLast().isOpen());
            assertThrows(IllegalArgumentException.class, () -> authority.requirePrefix(
                    new RevocationTransitionFeed.HighWatermark(OTHER_STORE_ID, prefix.globalRevision(), prefix.globalCommitment().value()),
                    prefix.boundary(), zeroecho.core.io.CancellationSignal.NONE));
            assertFalse(channels.getLast().isOpen());
            assertEquals(scans, authority.revocationLogScanInvocationCount());
        }
    }

    @Test
    void prefixCancellationBeforeOpenAndAfterEofPreservesCheckedFailureAndClosesChannel() throws Exception {
        for (boolean empty : List.of(true, false)) {
            Path root = temporaryDirectory.resolve("prefix-cancel-" + empty);
            try (FilesystemRevocationAuthority authority = authority(root, STORE_ID, true)) {
                if (!empty) append(authority, "credential:head", 1);
            }
            List<CountingChannel> channels = new ArrayList<>();
            IOException closeFailure = new IOException("controlled close failure");
            FilesystemRevocationAuthority.FeedChannelFactory factory = path -> {
                CountingChannel channel = new CountingChannel(FileChannel.open(path, StandardOpenOption.READ), new AtomicLong());
                channel.closeFailure = closeFailure;
                channels.add(channel);
                return channel;
            };
            try (FilesystemRevocationAuthority authority = FilesystemRevocationAuthority.open(new FsPaths(root), STORE_ID,
                    credentialId -> { }, false, FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE, factory)) {
                FilesystemRevocationLog.RecoveryTarget head = authority.head();
                assertThrows(InterruptedIOException.class, () -> authority.requirePrefix(watermark(head), head.boundary(), () -> true));
                assertTrue(channels.isEmpty());
                AtomicLong checks = new AtomicLong();
                InterruptedIOException cancelled = assertThrows(InterruptedIOException.class,
                        () -> authority.requirePrefix(watermark(head), head.boundary(), () -> checks.incrementAndGet() >= 2));
                assertEquals(2, checks.get());
                assertEquals(1, channels.size());
                assertFalse(channels.getFirst().isOpen());
                assertEquals(List.of(closeFailure), List.of(cancelled.getSuppressed()));
                assertEquals(closeFailure, assertThrows(IOException.class, () -> authority.requirePrefix(
                        watermark(head), head.boundary(), zeroecho.core.io.CancellationSignal.NONE)));
                assertFalse(channels.getLast().isOpen());
            }
        }
    }

    private static RevocationTransitionFeed.HighWatermark watermark(FilesystemRevocationLog.RecoveryTarget head) {
        return new RevocationTransitionFeed.HighWatermark(head.storeId(), head.globalRevision(), head.globalCommitment().value());
    }

    @Test
    void streamsGlobalAppendOrderWithCapturedHeadIsolation() throws Exception {
        try (FilesystemRevocationAuthority authority = authority(temporaryDirectory.resolve("ordered"), STORE_ID,
                true)) {
            append(authority, "credential:b", 1L);
            append(authority, "credential:a", 2L);
            try (RevocationTransitionFeed captured = authority.feed(Optional.empty())) {
                append(authority, "credential:c", 3L);
                assertEquals(2L, captured.highWatermark().globalRevision());
                List<String> identities = new ArrayList<>();
                while (captured.next()) {
                    RevocationTransitionFeed.Entry entry = captured.current();
                    assertEquals(identities.size() + 1L, entry.globalRevision());
                    assertEquals(STORE_ID, entry.sourceStoreId());
                    identities.add(entry.record().credentialId().value());
                }
                assertEquals(List.of("credential:b", "credential:a"), identities);
            }
            try (RevocationTransitionFeed current = authority.feed(Optional.empty())) {
                assertEquals(3L, current.highWatermark().globalRevision());
            }
        }
    }

    @Test
    void resumesInConstantPositionAfterRestart() throws Exception {
        Path root = temporaryDirectory.resolve("resume");
        RevocationTransitionFeed.Position position;
        try (FilesystemRevocationAuthority authority = authority(root, STORE_ID, true)) {
            append(authority, "credential:first", 1L);
            append(authority, "credential:second", 2L);
            try (RevocationTransitionFeed feed = authority.feed(Optional.empty())) {
                assertTrue(feed.next());
                position = feed.current().nextPosition();
            }
        }
        try (FilesystemRevocationAuthority reopened = authority(root, STORE_ID, false)) {
            long scans = reopened.revocationLogScanInvocationCount();
            try (RevocationTransitionFeed resumed = reopened.feed(Optional.of(position))) {
                assertEquals(scans, reopened.revocationLogScanInvocationCount());
                assertTrue(resumed.next());
                assertEquals(2L, resumed.current().globalRevision());
                assertEquals("credential:second", resumed.current().record().credentialId().value());
                assertFalse(resumed.next());
            }
            assertEquals(scans, reopened.revocationLogScanInvocationCount());
        }
    }

    @Test
    void rejectsForeignTamperedAndTruncatedPositions() throws Exception {
        Path firstRoot = temporaryDirectory.resolve("positions-first");
        RevocationTransitionFeed.Position position;
        try (FilesystemRevocationAuthority authority = authority(firstRoot, STORE_ID, true)) {
            append(authority, "credential:first-a", 1L);
            append(authority, "credential:second-a", 2L);
            try (RevocationTransitionFeed feed = authority.feed(Optional.empty())) {
                assertTrue(feed.next());
                position = feed.current().nextPosition();
            }
            String value = position.value();
            char replacement = value.charAt(value.length() - 1) == 'A' ? 'B' : 'A';
            RevocationTransitionFeed.Position tampered = new RevocationTransitionFeed.Position(
                    value.substring(0, value.length() - 1) + replacement);
            RevocationTransitionFeed.Position truncated = new RevocationTransitionFeed.Position(
                    value.substring(0, value.length() - 1));
            assertThrows(IllegalArgumentException.class, () -> authority.feed(Optional.of(tampered)));
            assertThrows(IllegalArgumentException.class, () -> authority.feed(Optional.of(truncated)));
        }
        try (FilesystemRevocationAuthority foreign = authority(temporaryDirectory.resolve("positions-other"),
                OTHER_STORE_ID, true)) {
            append(foreign, "credential:other", 1L);
            assertThrows(IllegalArgumentException.class, () -> foreign.feed(Optional.of(position)));
        }
        try (FilesystemRevocationAuthority mismatched = authority(
                temporaryDirectory.resolve("positions-mismatched"), STORE_ID, true)) {
            append(mismatched, "credential:first-b", 1L);
            append(mismatched, "credential:second-b", 2L);
            try (RevocationTransitionFeed lazy = mismatched.feed(Optional.of(position))) {
                assertThrows(IOException.class, lazy::next);
            }
        }
    }

    @Test
    void detectsCorruptionAndPreservesPositionOnCancellation() throws Exception {
        Path root = temporaryDirectory.resolve("corruption");
        FsPaths paths = new FsPaths(root);
        try (FilesystemRevocationAuthority authority = authority(root, STORE_ID, true)) {
            append(authority, "credential:first", 1L);
            append(authority, "credential:second", 2L);
            try (RevocationTransitionFeed cancelled = authority.feed(Optional.empty())) {
                assertTrue(cancelled.next());
                RevocationTransitionFeed.Entry first = cancelled.current();
                assertThrows(InterruptedIOException.class, () -> cancelled.next(() -> true));
                assertEquals(first, cancelled.current());
                assertTrue(cancelled.next());
                assertEquals(2L, cancelled.current().globalRevision());
            }
            try (RevocationTransitionFeed corrupted = authority.feed(Optional.empty());
                    FileChannel channel = FileChannel.open(paths.revocationTransitionLog(), StandardOpenOption.READ,
                            StandardOpenOption.WRITE)) {
                assertTrue(corrupted.next());
                RevocationTransitionFeed.Entry first = corrupted.current();
                long finalByte = channel.size() - 1L;
                ByteBuffer byteValue = ByteBuffer.allocate(1);
                assertEquals(1, channel.read(byteValue, finalByte));
                byteValue.flip();
                byte changed = (byte) (byteValue.get() ^ 0x01);
                assertEquals(1, channel.write(ByteBuffer.wrap(new byte[] { changed }), finalByte));
                assertThrows(IOException.class, corrupted::next);
                assertEquals(first, corrupted.current());
            }
        }
    }

    @Test
    void nonHeadOpenReadsOnlyFixedPreambleBeforeLargeSuccessor() throws Exception {
        Path root = temporaryDirectory.resolve("fixed-open");
        RevocationTransitionFeed.Position position;
        try (FilesystemRevocationAuthority authority = authority(root, STORE_ID, true)) {
            for (int index = 0; index < 32; index++) {
                append(authority, "credential:prefix-" + index, index + 1L);
            }
            byte[] large = new byte[LARGE_RECORD_BYTES];
            large[large.length - 1] = 1;
            AttributeSet attributes = SimpleAttributeSet.builder().put(new AttributeId("test.large-unread"),
                    new AttributeValue.BytesValue(large)).build();
            append(authority, "credential:large", 33L, attributes);
            try (RevocationTransitionFeed feed = authority.feed(Optional.empty())) {
                for (int index = 0; index < 32; index++) {
                    assertTrue(feed.next());
                }
                position = feed.current().nextPosition();
            }
        }

        AtomicLong bytesRead = new AtomicLong();
        FilesystemRevocationAuthority.FeedChannelFactory counted = path -> new CountingChannel(
                FileChannel.open(path, StandardOpenOption.READ), bytesRead);
        try (FilesystemRevocationAuthority reopened = FilesystemRevocationAuthority.open(new FsPaths(root),
                STORE_ID, credentialId -> { }, false,
                FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE, counted)) {
            long beforeOpen = bytesRead.get();
            try (RevocationTransitionFeed feed = reopened.feed(Optional.of(position))) {
                assertEquals(RevocationTransitionFrameCodec.PREAMBLE_BYTES, bytesRead.get() - beforeOpen);
                assertTrue(feed.next());
                assertEquals("credential:large", feed.current().record().credentialId().value());
                assertTrue(bytesRead.get() - beforeOpen > LARGE_RECORD_BYTES);
            }
        }
    }

    @Test
    void reusesOneExactDecodeScratchPerFeedAndNeverSharesBetweenFeeds() throws Exception {
        Path root = temporaryDirectory.resolve("decode-scratch");
        try (FilesystemRevocationAuthority authority = authority(root, STORE_ID, true)) {
            append(authority, "credential:first", 1L);
            append(authority, "credential:second", 2L);
            append(authority, "credential:third", 3L);
        }

        List<ScratchTrackingChannel> channels = new ArrayList<>();
        FilesystemRevocationAuthority.FeedChannelFactory tracked = path -> {
            ScratchTrackingChannel channel = new ScratchTrackingChannel(
                    FileChannel.open(path, StandardOpenOption.READ));
            channels.add(channel);
            return channel;
        };
        try (FilesystemRevocationAuthority reopened = FilesystemRevocationAuthority.open(new FsPaths(root),
                STORE_ID, credentialId -> { }, false,
                FilesystemRevocationAuthority.IndexUpdateFaultInjector.NONE, tracked);
                RevocationTransitionFeed first = reopened.feed(Optional.empty());
                RevocationTransitionFeed second = reopened.feed(Optional.empty())) {
            assertEquals(16 * 1024, RevocationTransitionFrameCodec.READ_SCRATCH_BYTES);
            while (first.next()) {
                assertTrue(first.current().globalRevision() <= 3L);
            }
            assertTrue(second.next());
            assertTrue(second.next());
            assertEquals(2, channels.size());
            assertEquals(1, channels.get(0).scratchBuffers().size());
            assertEquals(1, channels.get(1).scratchBuffers().size());
            byte[] firstScratch = channels.get(0).scratchBuffers().iterator().next();
            byte[] secondScratch = channels.get(1).scratchBuffers().iterator().next();
            assertEquals(RevocationTransitionFrameCodec.READ_SCRATCH_BYTES, firstScratch.length);
            assertEquals(RevocationTransitionFrameCodec.READ_SCRATCH_BYTES, secondScratch.length);
            assertNotSame(firstScratch, secondScratch);
        }
    }

    @Test
    void emptyAndClosedFeedsFailAtDocumentedBoundaries() throws Exception {
        FilesystemRevocationAuthority authority = authority(temporaryDirectory.resolve("lifecycle"), STORE_ID, true);
        RevocationTransitionFeed feed = authority.feed(Optional.empty());
        assertEquals(0L, feed.highWatermark().globalRevision());
        assertFalse(feed.next());
        assertThrows(IllegalStateException.class, feed::current);
        feed.close();
        feed.close();
        assertThrows(IllegalStateException.class, feed::highWatermark);
        assertThrows(IllegalStateException.class, feed::next);
        RevocationTransitionFeed ownerClosed = authority.feed(Optional.empty());
        authority.close();
        assertThrows(IllegalStateException.class, ownerClosed::next);
    }

    private static FilesystemRevocationAuthority authority(Path root, MetadataStoreId storeId, boolean create)
            throws IOException {
        return FilesystemRevocationAuthority.open(new FsPaths(root), storeId, credentialId -> { }, create);
    }

    private static void append(FilesystemRevocationAuthority authority, String credentialId, long second)
            throws IOException {
        append(authority, credentialId, second, new SimpleAttributeSet());
    }

    private static void append(FilesystemRevocationAuthority authority, String credentialId, long second,
            AttributeSet attributes) throws IOException {
        authority.append(new PkiId(credentialId), new RevocationTransition(1L, RevocationState.HELD,
                Instant.ofEpochSecond(second), Optional.empty(), attributes));
    }

    private static final class CountingChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;
        private final AtomicLong bytesRead;
        private IOException closeFailure;

        private CountingChannel(SeekableByteChannel delegate, AtomicLong bytesRead) {
            this.delegate = delegate;
            this.bytesRead = bytesRead;
        }

        @Override public int read(ByteBuffer destination) throws IOException {
            int count = delegate.read(destination);
            if (count > 0) {
                bytesRead.addAndGet(count);
            }
            return count;
        }
        @Override public int write(ByteBuffer source) throws IOException { return delegate.write(source); }
        @Override public long position() throws IOException { return delegate.position(); }
        @Override public SeekableByteChannel position(long position) throws IOException {
            delegate.position(position); return this;
        }
        @Override public long size() throws IOException { return delegate.size(); }
        @Override public SeekableByteChannel truncate(long size) throws IOException {
            delegate.truncate(size); return this;
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() throws IOException {
            delegate.close();
            if (closeFailure != null) throw closeFailure;
        }
    }

    /** Observes only backing-array identity and never mutates caller buffers. */
    private static final class ScratchTrackingChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;
        private final Set<byte[]> scratchBuffers = Collections.newSetFromMap(new IdentityHashMap<>());

        private ScratchTrackingChannel(SeekableByteChannel delegate) {
            this.delegate = delegate;
        }

        private Set<byte[]> scratchBuffers() {
            return Set.copyOf(scratchBuffers);
        }

        @Override public int read(ByteBuffer destination) throws IOException {
            if (destination.hasArray()
                    && destination.array().length == RevocationTransitionFrameCodec.READ_SCRATCH_BYTES) {
                scratchBuffers.add(destination.array());
            }
            return delegate.read(destination);
        }
        @Override public int write(ByteBuffer source) throws IOException { return delegate.write(source); }
        @Override public long position() throws IOException { return delegate.position(); }
        @Override public SeekableByteChannel position(long position) throws IOException {
            delegate.position(position); return this;
        }
        @Override public long size() throws IOException { return delegate.size(); }
        @Override public SeekableByteChannel truncate(long size) throws IOException {
            delegate.truncate(size); return this;
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() throws IOException { delegate.close(); }
    }
}
