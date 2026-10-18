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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class SigningCommittedPrefixReaderTest {

    @TempDir
    private Path temporaryDirectory;

    @Test
    void rejectsTruncationAndForcedEndInsideACommittedGroup() throws Exception {
        Fixture fixture = new Fixture();
        Endpoint committed = fixture.append(List.of(frame(0L), frame(1L)), 2L);
        CommittedPrefixDescriptor descriptor = fixture.descriptor(fixture.baseline, committed);

        Path truncated = write("truncated.zew",
                java.util.Arrays.copyOf(fixture.bytes(), fixture.bytes().length - 1));
        try (SeekableByteChannel channel = Files.newByteChannel(truncated,
                StandardOpenOption.READ)) {
            assertThrows(IOException.class, () -> SigningCommittedPrefixReader.read(
                    channel, descriptor, 0L, 2L, ignored -> { }));
        }

        CommittedPrefixDescriptor insideGroup = new CommittedPrefixDescriptor(
                descriptor.generationId(), descriptor.exclusiveStartOffset(),
                descriptor.exclusiveStartSequence(), descriptor.exclusiveStartRevision(),
                descriptor.exclusiveStartCommitment(),
                descriptor.inclusiveForcedEndOffset() - 1L,
                descriptor.inclusiveForcedEndSequence(),
                descriptor.inclusiveForcedEndRevision(),
                descriptor.inclusiveForcedEndCommitment());
        Path complete = write("inside-group.zew", fixture.bytes());
        try (SeekableByteChannel channel = Files.newByteChannel(complete,
                StandardOpenOption.READ)) {
            assertThrows(IOException.class, () -> SigningCommittedPrefixReader.read(
                    channel, insideGroup, 0L, 2L, ignored -> { }));
        }
    }

    @Test
    void rejectsCommitmentSequenceAndRevisionEndpointMismatch() throws Exception {
        Fixture fixture = new Fixture();
        Endpoint committed = fixture.append(List.of(frame(0L)), 1L);
        CommittedPrefixDescriptor valid = fixture.descriptor(fixture.baseline, committed);
        Path path = write("mismatch.zew", fixture.bytes());

        byte[] wrongCommitment = valid.inclusiveForcedEndCommitment();
        wrongCommitment[0] ^= 1;
        CommittedPrefixDescriptor commitmentMismatch = descriptor(valid,
                valid.inclusiveForcedEndSequence(), valid.inclusiveForcedEndRevision(),
                wrongCommitment);
        assertRejected(path, commitmentMismatch);

        CommittedPrefixDescriptor sequenceMismatch = descriptor(valid,
                valid.inclusiveForcedEndSequence() + 1L,
                valid.inclusiveForcedEndRevision(), valid.inclusiveForcedEndCommitment());
        assertRejected(path, sequenceMismatch);

        CommittedPrefixDescriptor revisionMismatch = descriptor(valid,
                valid.inclusiveForcedEndSequence(),
                valid.inclusiveForcedEndRevision() + 1L,
                valid.inclusiveForcedEndCommitment());
        assertRejected(path, revisionMismatch);
    }

    @Test
    void neverReadsPastTheForcedEndWhenTheFileAlreadyContainsAnotherGroup() throws Exception {
        Fixture fixture = new Fixture();
        Endpoint first = fixture.append(List.of(frame(0L)), 1L);
        fixture.append(List.of(frame(1L)), 2L);
        CommittedPrefixDescriptor firstOnly = fixture.descriptor(fixture.baseline, first);
        Path path = write("bounded-read.zew", fixture.bytes());

        try (TrackingChannel channel = new TrackingChannel(FileChannel.open(path,
                StandardOpenOption.READ))) {
            SigningCommittedPrefixReader.Result result = SigningCommittedPrefixReader.read(
                    channel, firstOnly, 0L, 1L, ignored -> { });
            assertTrue(result.forcedAndProjectedEndpointsEqual());
            assertTrue(channel.maximumReadPosition <= firstOnly.inclusiveForcedEndOffset());
        }
    }

    @Test
    void partialGroupRereadDoesNotAdvanceAndAppliesNewlyProjectedFramesExactlyOnce()
            throws Exception {
        Fixture fixture = new Fixture();
        Endpoint committed = fixture.append(List.of(frame(0L), frame(1L)), 2L);
        CommittedPrefixDescriptor descriptor = fixture.descriptor(fixture.baseline, committed);
        Path path = write("partial-reread.zew", fixture.bytes());

        try (SeekableByteChannel channel = Files.newByteChannel(path, StandardOpenOption.READ)) {
            SigningCommittedPrefixReader.Result partial = SigningCommittedPrefixReader.read(
                    channel, descriptor, 0L, 1L, ignored -> {
                        throw new AssertionError("partial group must not apply");
                    });
            assertEquals(descriptor.exclusiveStartOffset(),
                    partial.acceptedPrefix().inclusiveForcedEndOffset());
            assertEquals(0L, partial.appliedFrames());
            assertFalse(partial.forcedAndProjectedEndpointsEqual());
        }

        List<Long> applied = new ArrayList<>();
        SigningCommittedPrefixReader.Result completed;
        try (SeekableByteChannel channel = Files.newByteChannel(path, StandardOpenOption.READ)) {
            completed = SigningCommittedPrefixReader.read(channel, descriptor, 1L, 2L,
                    scanned -> applied.add(scanned.revision()));
        }
        assertEquals(List.of(2L), applied);
        assertEquals(1L, completed.appliedFrames());
        assertTrue(completed.forcedAndProjectedEndpointsEqual());

        CommittedPrefixDescriptor empty = new CommittedPrefixDescriptor(
                descriptor.generationId(),
                completed.acceptedPrefix().inclusiveForcedEndOffset(),
                completed.acceptedPrefix().inclusiveForcedEndSequence(),
                completed.acceptedPrefix().inclusiveForcedEndRevision(),
                completed.acceptedPrefix().inclusiveForcedEndCommitment(),
                completed.acceptedPrefix().inclusiveForcedEndOffset(),
                completed.acceptedPrefix().inclusiveForcedEndSequence(),
                completed.acceptedPrefix().inclusiveForcedEndRevision(),
                completed.acceptedPrefix().inclusiveForcedEndCommitment());
        try (SeekableByteChannel channel = Files.newByteChannel(path, StandardOpenOption.READ)) {
            SigningCommittedPrefixReader.Result repeated = SigningCommittedPrefixReader.read(
                    channel, empty, 2L, 2L, ignored -> {
                        throw new AssertionError("accepted revision must not be applied twice");
                    });
            assertEquals(0L, repeated.appliedFrames());
            assertTrue(repeated.forcedAndProjectedEndpointsEqual());
        }
    }

    private void assertRejected(Path path, CommittedPrefixDescriptor descriptor) throws Exception {
        try (SeekableByteChannel channel = Files.newByteChannel(path, StandardOpenOption.READ)) {
            assertThrows(IOException.class, () -> SigningCommittedPrefixReader.read(
                    channel, descriptor, 0L, 1L, ignored -> { }));
        }
    }

    private Path write(String name, byte[] content) throws IOException {
        Path path = temporaryDirectory.resolve(name);
        Files.write(path, content);
        return path;
    }

    private static CommittedPrefixDescriptor descriptor(CommittedPrefixDescriptor source,
            long endSequence, long endRevision, byte[] endCommitment) {
        return new CommittedPrefixDescriptor(source.generationId(),
                source.exclusiveStartOffset(), source.exclusiveStartSequence(),
                source.exclusiveStartRevision(), source.exclusiveStartCommitment(),
                source.inclusiveForcedEndOffset(), endSequence, endRevision, endCommitment);
    }

    private static SigningWalFrameCodec.Frame frame(long sequence) {
        return new SigningWalFrameCodec.Frame(SigningWalFrameCodec.RecordType.MUTATION,
                new UUID(0L, sequence + 1L), sequence, new byte[] { (byte) sequence });
    }

    private static final class Fixture {
        private static final long GENERATION = 7L;
        private final ByteArrayOutputStream output = new ByteArrayOutputStream();
        private final Endpoint baseline;
        private Endpoint current;

        private Fixture() throws IOException {
            byte[] header = SigningWalContainerCodec.encode(
                    new SigningWalContainerCodec.Header(GENERATION, 0L, 0L));
            output.write(header);
            baseline = new Endpoint(SigningWalContainerCodec.HEADER_BYTES,
                    -1L, 0L, SigningFormatSupport.sha256().digest(header));
            current = baseline;
        }

        private Endpoint append(List<SigningWalFrameCodec.Frame> frames,
                long committedRevision) throws IOException {
            SigningWalFrameCodec.BatchCommit commit = SigningWalFrameCodec.writeCommittedBatch(
                    Channels.newChannel(output), frames, current.revision,
                    committedRevision, current.commitment);
            current = new Endpoint(output.size(), commit.endSequence(),
                    commit.committedRevision(), commit.resultingCommitment());
            return current;
        }

        private CommittedPrefixDescriptor descriptor(Endpoint start, Endpoint end) {
            return new CommittedPrefixDescriptor(GENERATION, start.offset, start.sequence,
                    start.revision, start.commitment, end.offset, end.sequence,
                    end.revision, end.commitment);
        }

        private byte[] bytes() {
            return output.toByteArray();
        }
    }

    private record Endpoint(long offset, long sequence, long revision, byte[] commitment) {
        private Endpoint {
            commitment = commitment.clone();
        }
    }

    private static final class TrackingChannel implements SeekableByteChannel {
        private final FileChannel delegate;
        private long maximumReadPosition;

        private TrackingChannel(FileChannel delegate) {
            this.delegate = delegate;
        }

        @Override
        public int read(ByteBuffer target) throws IOException {
            int count = delegate.read(target);
            maximumReadPosition = Math.max(maximumReadPosition, delegate.position());
            return count;
        }

        @Override public int write(ByteBuffer source) { throw new UnsupportedOperationException(); }
        @Override public long position() throws IOException { return delegate.position(); }
        @Override public SeekableByteChannel position(long position) throws IOException {
            delegate.position(position);
            return this;
        }
        @Override public long size() throws IOException { return delegate.size(); }
        @Override public SeekableByteChannel truncate(long size) {
            throw new UnsupportedOperationException();
        }
        @Override public boolean isOpen() { return delegate.isOpen(); }
        @Override public void close() throws IOException { delegate.close(); }
    }
}
