/*******************************************************************************
 * Copyright (C) 2026, Leo Galambos
 * All rights reserved.
 ******************************************************************************/
package zeroecho.pki.impl.fs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.OptionalLong;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.ImmutableByteContent;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.spi.store.MetadataCommitResult;
import zeroecho.pki.spi.store.MetadataKey;
import zeroecho.pki.spi.store.MetadataStoreException;

final class MetadataMutationPayloadCodecTest {
    private static final String TOKEN = "00000000000000000000000000000001";
    private static final int COMMON_BYTES = 8;
    private static final int CREATE_SCALAR_BYTES = Long.BYTES;
    private final AtomicInteger fixtureNumber = new AtomicInteger();

    @TempDir
    Path temporaryDirectory;

    @Test
    void createReplaceAndDeleteDescriptorsRoundTripWithoutReadingValues() throws IOException {
        System.out.print("createReplaceAndDeleteDescriptorsRoundTripWithoutReadingValues ");
        MetadataKey key = new MetadataKey("example.audit", "record-1");
        try (ImmutableByteContent value = new ImmutableByteContent(new byte[] { 1, 2, 3, 4 })) {
            assertDescriptor(
                    MetadataMutationPayloadCodec.create(key, value, CancellationSignal.NONE),
                    MetadataFrameCodec.FrameType.MUTATION_CREATE,
                    MetadataMutationPayloadCodec.MutationKind.CREATE,
                    key,
                    OptionalLong.empty(),
                    4L);
            assertDescriptor(
                    MetadataMutationPayloadCodec.replace(key, 7L, value, CancellationSignal.NONE),
                    MetadataFrameCodec.FrameType.MUTATION_REPLACE,
                    MetadataMutationPayloadCodec.MutationKind.REPLACE,
                    key,
                    OptionalLong.of(7L),
                    4L);
        }
        MetadataMutationPayloadCodec.Descriptor deleted = decode(
                bytes(MetadataMutationPayloadCodec.delete(key, 9L)),
                MetadataFrameCodec.FrameType.MUTATION_DELETE);
        assertEquals(MetadataMutationPayloadCodec.MutationKind.DELETE, deleted.kind());
        assertEquals(OptionalLong.of(9L), deleted.expectedRevision());
        assertTrue(deleted.valueOffset().isEmpty());
        assertTrue(deleted.valueLength().isEmpty());
        System.out.println("...ok");
    }

    @Test
    void identityBoundariesAndStrictDescriptorSchemasFailClosed() throws IOException {
        System.out.print("identityBoundariesAndStrictDescriptorSchemasFailClosed ");
        MetadataKey boundary = new MetadataKey("n".repeat(255), "k".repeat(4096));
        try (ImmutableByteContent empty = new ImmutableByteContent(new byte[0])) {
            MetadataMutationPayloadCodec.Descriptor descriptor = decode(
                    bytes(MetadataMutationPayloadCodec.create(boundary, empty, CancellationSignal.NONE)),
                    MetadataFrameCodec.FrameType.MUTATION_CREATE);
            assertEquals(boundary, descriptor.key());
        }
        byte[] valid = createBytes(new MetadataKey("example.audit", "key"), new byte[] { 5 });
        assertIntegrity(change(valid, 0, (byte) 2), MetadataFrameCodec.FrameType.MUTATION_CREATE);
        assertIntegrity(change(valid, 2, (byte) 99), MetadataFrameCodec.FrameType.MUTATION_CREATE);
        assertIntegrity(change(valid, 3, (byte) 1), MetadataFrameCodec.FrameType.MUTATION_CREATE);
        byte[] oversizedNamespace = valid.clone();
        ByteBuffer.wrap(oversizedNamespace).order(ByteOrder.BIG_ENDIAN).putShort(4, (short) 256);
        assertIntegrity(oversizedNamespace, MetadataFrameCodec.FrameType.MUTATION_CREATE);
        byte[] malformedUtf8 = valid.clone();
        malformedUtf8[COMMON_BYTES + CREATE_SCALAR_BYTES] = (byte) 0xc3;
        assertIntegrity(malformedUtf8, MetadataFrameCodec.FrameType.MUTATION_CREATE);
        byte[] negativeLength = valid.clone();
        ByteBuffer.wrap(negativeLength).order(ByteOrder.BIG_ENDIAN).putLong(COMMON_BYTES, -1L);
        assertIntegrity(negativeLength, MetadataFrameCodec.FrameType.MUTATION_CREATE);
        assertIntegrity(Arrays.copyOf(valid, valid.length + 1), MetadataFrameCodec.FrameType.MUTATION_CREATE);
        assertIntegrity(valid, MetadataFrameCodec.FrameType.MUTATION_REPLACE);
        assertIntegrityAtOverflow(valid);
        System.out.println("...ok");
    }

    @Test
    void compositeStreamingDetachesNoCallerAuthorityAndChecksExactLength() throws IOException {
        System.out.print("compositeStreamingDetachesNoCallerAuthorityAndChecksExactLength ");
        MetadataKey key = new MetadataKey("example.audit", "stream");
        byte[] generated = new byte[25_000];
        Arrays.fill(generated, (byte) 7);
        ProbeContent exact = new ProbeContent(generated, OptionalLong.of(generated.length));
        RepeatableContent encoded = MetadataMutationPayloadCodec.create(key, exact, CancellationSignal.NONE);
        byte[] payload = bytes(encoded);
        assertEquals(1, exact.openCount.get());
        assertTrue(exact.streamClosed);
        encoded.close();
        assertFalse(exact.contentClosed);
        MetadataMutationPayloadCodec.Descriptor descriptor = decode(
                payload, MetadataFrameCodec.FrameType.MUTATION_CREATE);
        assertEquals(generated.length, descriptor.valueLength().orElseThrow());
        assertEquals(16L + key.namespace().length() + key.key().length(),
                descriptor.valueOffset().orElseThrow());

        ProbeContent shortValue = new ProbeContent(new byte[] { 1 }, OptionalLong.of(2L));
        assertThrows(IOException.class, () -> bytes(
                MetadataMutationPayloadCodec.create(key, shortValue, CancellationSignal.NONE)));
        ProbeContent excessValue = new ProbeContent(new byte[] { 1, 2 }, OptionalLong.of(1L));
        assertThrows(IOException.class, () -> bytes(
                MetadataMutationPayloadCodec.create(key, excessValue, CancellationSignal.NONE)));
        ProbeContent unknown = new ProbeContent(new byte[0], OptionalLong.empty());
        MetadataStoreException unsupported = assertThrows(MetadataStoreException.class,
                () -> MetadataMutationPayloadCodec.create(key, unknown, CancellationSignal.NONE));
        assertEquals(MetadataCommitResult.FailureCategory.UNSUPPORTED_CAPABILITY, unsupported.category());
        ProbeContent overflow = new ProbeContent(new byte[0], OptionalLong.of(Long.MAX_VALUE));
        MetadataStoreException limited = assertThrows(MetadataStoreException.class,
                () -> MetadataMutationPayloadCodec.create(key, overflow, CancellationSignal.NONE));
        assertEquals(MetadataCommitResult.FailureCategory.LIMIT_EXCEEDED, limited.category());
        System.out.println("...ok");
    }

    @Test
    void cancellationIsObservedBeforeOpenAndBetweenBoundedReads() throws IOException {
        System.out.print("cancellationIsObservedBeforeOpenAndBetweenBoundedReads ");
        MetadataKey key = new MetadataKey("example.audit", "cancel");
        ProbeContent before = new ProbeContent(new byte[] { 1 }, OptionalLong.of(1L));
        RepeatableContent cancelled = MetadataMutationPayloadCodec.create(key, before, () -> true);
        assertThrows(IOException.class, cancelled::openStream);
        assertEquals(0, before.openCount.get());

        ProbeContent during = new ProbeContent(new byte[30_000], OptionalLong.of(30_000L));
        AtomicInteger checks = new AtomicInteger();
        CancellationSignal signal = () -> checks.incrementAndGet() > 4;
        RepeatableContent interrupted = MetadataMutationPayloadCodec.create(key, during, signal);
        assertThrows(IOException.class, () -> bytes(interrupted));
        assertTrue(during.streamClosed);
        assertTrue(during.bytesRead < 30_000);
        System.out.println("...ok");
    }

    @Test
    void zeroProgressFromCallerContentFailsOnceAndClosesTheStream() throws IOException {
        System.out.print("zeroProgressFromCallerContentFailsOnceAndClosesTheStream ");
        MetadataKey key = new MetadataKey("example.audit", "zero-progress");
        ZeroProgressContent beforeData = new ZeroProgressContent(false);
        MetadataStoreException beforeFailure = assertThrows(
                MetadataStoreException.class,
                () -> bytes(MetadataMutationPayloadCodec.create(
                        key, beforeData, CancellationSignal.NONE)));
        assertEquals(MetadataCommitResult.FailureCategory.STORAGE_FAILURE, beforeFailure.category());
        assertEquals(1, beforeData.readCalls);
        assertTrue(beforeData.streamClosed);

        ZeroProgressContent afterData = new ZeroProgressContent(true);
        MetadataStoreException afterFailure = assertThrows(
                MetadataStoreException.class,
                () -> bytes(MetadataMutationPayloadCodec.create(
                        key, afterData, CancellationSignal.NONE)));
        assertEquals(MetadataCommitResult.FailureCategory.STORAGE_FAILURE, afterFailure.category());
        assertEquals(2, afterData.readCalls);
        assertTrue(afterData.streamClosed);
        System.out.println("...ok");
    }

    @Test
    void boundedDecodeRejectsZeroProgressAndInvalidRegionsWithoutClosingChannel() throws IOException {
        System.out.print("boundedDecodeRejectsZeroProgressAndInvalidRegionsWithoutClosingChannel ");
        byte[] payload = createBytes(new MetadataKey("example.audit", "bounded"), new byte[] { 1 });
        Path path = temporaryDirectory.resolve("zero-progress-channel");
        java.nio.file.Files.write(path, payload);
        try (FileChannel delegate = FileChannel.open(path, StandardOpenOption.READ)) {
            ZeroProgressChannel channel = new ZeroProgressChannel(delegate);
            MetadataStoreException zeroProgress = assertThrows(
                    MetadataStoreException.class,
                    () -> MetadataMutationPayloadCodec.decode(
                            channel,
                            metadata(MetadataFrameCodec.FrameType.MUTATION_CREATE, payload.length, 0L)));
            assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, zeroProgress.category());
            assertEquals(1, channel.readCalls);
            assertTrue(channel.isOpen());
        }

        assertIntegrityWithMetadata(payload, metadata(
                MetadataFrameCodec.FrameType.MUTATION_CREATE, payload.length, -1L));
        assertIntegrityWithMetadata(payload, new MetadataFrameCodec.FrameMetadata(
                MetadataFrameCodec.FrameType.MUTATION_CREATE,
                TOKEN,
                1L,
                0L,
                0L,
                -1L,
                -1L,
                -1L));
        assertIntegrityWithMetadata(payload, metadata(
                MetadataFrameCodec.FrameType.MUTATION_CREATE, payload.length - 1L, 0L));
        assertIntegrityWithMetadata(payload, metadata(
                MetadataFrameCodec.FrameType.MUTATION_CREATE, payload.length + 1L, 0L));
        assertIntegrityAtOverflow(payload);
        System.out.println("...ok");
    }

    private void assertDescriptor(
            RepeatableContent content,
            MetadataFrameCodec.FrameType frameType,
            MetadataMutationPayloadCodec.MutationKind kind,
            MetadataKey key,
            OptionalLong expectedRevision,
            long valueLength) throws IOException {
        byte[] payload = bytes(content);
        MetadataMutationPayloadCodec.Descriptor descriptor = decode(payload, frameType);
        assertEquals(kind, descriptor.kind());
        assertEquals(key, descriptor.key());
        assertEquals(expectedRevision, descriptor.expectedRevision());
        assertEquals(valueLength, descriptor.valueLength().orElseThrow());
        assertTrue(descriptor.valueOffset().orElseThrow() < payload.length);
    }

    private byte[] createBytes(MetadataKey key, byte[] value) throws IOException {
        try (ImmutableByteContent content = new ImmutableByteContent(value)) {
            return bytes(MetadataMutationPayloadCodec.create(key, content, CancellationSignal.NONE));
        }
    }

    private MetadataMutationPayloadCodec.Descriptor decode(
            byte[] payload, MetadataFrameCodec.FrameType frameType) throws IOException {
        Path path = temporaryDirectory.resolve("payload-" + fixtureNumber.incrementAndGet());
        java.nio.file.Files.write(path, payload);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            MetadataMutationPayloadCodec.Descriptor descriptor = MetadataMutationPayloadCodec.decode(
                    channel, metadata(frameType, payload.length, 0L));
            if (descriptor.valueOffset().isPresent()) {
                assertEquals(descriptor.valueOffset().getAsLong(), channel.position());
            }
            return descriptor;
        }
    }

    private void assertIntegrity(byte[] payload, MetadataFrameCodec.FrameType frameType) {
        MetadataStoreException failure = assertThrows(
                MetadataStoreException.class, () -> decode(payload, frameType));
        assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, failure.category());
    }

    private void assertIntegrityAtOverflow(byte[] payload) throws IOException {
        Path path = temporaryDirectory.resolve("overflow");
        java.nio.file.Files.write(path, payload);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            MetadataFrameCodec.FrameMetadata overflow = metadata(
                    MetadataFrameCodec.FrameType.MUTATION_CREATE,
                    payload.length,
                    Long.MAX_VALUE - 2L);
            MetadataStoreException failure = assertThrows(
                    MetadataStoreException.class,
                    () -> MetadataMutationPayloadCodec.decode(channel, overflow));
            assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, failure.category());
        }
    }

    private void assertIntegrityWithMetadata(
            byte[] payload, MetadataFrameCodec.FrameMetadata frame) throws IOException {
        Path path = temporaryDirectory.resolve("invalid-region-" + fixtureNumber.incrementAndGet());
        java.nio.file.Files.write(path, payload);
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            MetadataStoreException failure = assertThrows(
                    MetadataStoreException.class,
                    () -> MetadataMutationPayloadCodec.decode(channel, frame));
            assertEquals(MetadataCommitResult.FailureCategory.INTEGRITY_FAILURE, failure.category());
        }
    }

    private static MetadataFrameCodec.FrameMetadata metadata(
            MetadataFrameCodec.FrameType type, long payloadLength, long payloadOffset) {
        long digestOffset;
        try {
            digestOffset = Math.addExact(payloadOffset, payloadLength);
        } catch (ArithmeticException failure) {
            digestOffset = Long.MAX_VALUE;
        }
        return new MetadataFrameCodec.FrameMetadata(
                type, TOKEN, 1L, 0L, payloadOffset, payloadLength, digestOffset, digestOffset);
    }

    private static byte[] bytes(RepeatableContent content) throws IOException {
        try (InputStream input = content.openStream(); ByteArrayOutputStream output = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            while (true) {
                int count = input.read(buffer);
                if (count < 0) {
                    return output.toByteArray();
                }
                output.write(buffer, 0, count);
            }
        }
    }

    private static byte[] change(byte[] source, int offset, byte value) {
        byte[] result = source.clone();
        result[offset] = value;
        return result;
    }

    private static final class ProbeContent implements RepeatableContent {
        private final byte[] value;
        private final OptionalLong declaredLength;
        private final AtomicInteger openCount = new AtomicInteger();
        private boolean streamClosed;
        private boolean contentClosed;
        private int bytesRead;

        private ProbeContent(byte[] value, OptionalLong declaredLength) {
            this.value = value.clone();
            this.declaredLength = declaredLength;
        }

        @Override
        public InputStream openStream() {
            openCount.incrementAndGet();
            return new ByteArrayInputStream(value) {
                @Override
                public synchronized int read(byte[] target, int offset, int length) {
                    int count = super.read(target, offset, length);
                    if (count > 0) {
                        bytesRead += count;
                    }
                    return count;
                }

                @Override
                public void close() throws IOException {
                    streamClosed = true;
                    super.close();
                }
            };
        }

        @Override
        public OptionalLong length() {
            return declaredLength;
        }

        @Override
        public String contentId() {
            return "probe-content";
        }

        @Override
        public void close() {
            contentClosed = true;
        }
    }

    private static final class ZeroProgressContent implements RepeatableContent {
        private final boolean emitDataFirst;
        private int readCalls;
        private boolean streamClosed;

        private ZeroProgressContent(boolean emitDataFirst) {
            this.emitDataFirst = emitDataFirst;
        }

        @Override
        public InputStream openStream() {
            return new InputStream() {
                @Override
                public int read() {
                    return -1;
                }

                @Override
                public int read(byte[] target, int offset, int length) {
                    readCalls++;
                    if (emitDataFirst && readCalls == 1) {
                        target[offset] = 1;
                        return 1;
                    }
                    return 0;
                }

                @Override
                public void close() {
                    streamClosed = true;
                }
            };
        }

        @Override
        public OptionalLong length() {
            return OptionalLong.of(emitDataFirst ? 2L : 1L);
        }

        @Override
        public String contentId() {
            return "zero-progress-content";
        }

        @Override
        public void close() {
            // The probe owns no resource outside each stream it opens.
        }
    }

    private static final class ZeroProgressChannel implements SeekableByteChannel {
        private final SeekableByteChannel delegate;
        private int readCalls;

        private ZeroProgressChannel(SeekableByteChannel delegate) {
            this.delegate = delegate;
        }

        @Override
        public int read(ByteBuffer destination) {
            readCalls++;
            return 0;
        }

        @Override
        public int write(ByteBuffer source) throws IOException {
            return delegate.write(source);
        }

        @Override
        public long position() throws IOException {
            return delegate.position();
        }

        @Override
        public SeekableByteChannel position(long newPosition) throws IOException {
            delegate.position(newPosition);
            return this;
        }

        @Override
        public long size() throws IOException {
            return delegate.size();
        }

        @Override
        public SeekableByteChannel truncate(long size) throws IOException {
            delegate.truncate(size);
            return this;
        }

        @Override
        public boolean isOpen() {
            return delegate.isOpen();
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
