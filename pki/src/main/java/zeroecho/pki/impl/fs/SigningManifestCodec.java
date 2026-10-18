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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

/** Canonical version-one signing manifest codec. */
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.PreserveStackTrace",
        "PMD.PrematureDeclaration" })
final class SigningManifestCodec {

    /* default */ static final int MAGIC = 0x5A454D53;
    /* default */ static final short VERSION = 1;
    /* default */ static final int MAX_SEGMENTS = 4096;
    /* default */ static final int MAX_NAME_BYTES = 96;
    /* default */ static final long MAX_FILE_BYTES = 1L << 40;

    private static final short FLAGS = 0;
    private static final int FIXED_PREFIX_BYTES = 36;
    private static final int CHECKPOINT_FIXED_BYTES = 66;
    private static final int SEGMENT_FIXED_BYTES = 66;
    private static final int ACTIVE_FIXED_BYTES = 66;
    private static final int COMMITMENT_BYTES = SigningFormatSupport.SHA_256_BYTES;
    /* default */ static final int MAX_ENCODED_BYTES = FIXED_PREFIX_BYTES + CHECKPOINT_FIXED_BYTES
            + MAX_NAME_BYTES + MAX_SEGMENTS * (SEGMENT_FIXED_BYTES + MAX_NAME_BYTES)
            + ACTIVE_FIXED_BYTES + MAX_NAME_BYTES + COMMITMENT_BYTES;

    private SigningManifestCodec() {
        // utility class
    }

    /* default */ static byte[] encode(Manifest manifest) {
        validate(manifest);
        int length = FIXED_PREFIX_BYTES + ACTIVE_FIXED_BYTES + COMMITMENT_BYTES
                + encodedName(manifest.activeWal().name()).length;
        if (manifest.checkpoint().isPresent()) {
            length = Math.addExact(length, CHECKPOINT_FIXED_BYTES
                    + encodedName(manifest.checkpoint().orElseThrow().name()).length);
        }
        for (Segment segment : manifest.sealedSegments()) {
            length = Math.addExact(length, SEGMENT_FIXED_BYTES + encodedName(segment.name()).length);
        }
        ByteBuffer output = ByteBuffer.allocate(length).order(ByteOrder.BIG_ENDIAN);
        output.putInt(MAGIC);
        output.putShort(VERSION);
        output.putShort(FLAGS);
        output.putInt(length);
        output.putLong(manifest.committedRevision());
        output.putLong(manifest.committedSequence());
        output.put((byte) (manifest.checkpoint().isPresent() ? 1 : 0));
        output.put(new byte[3]);
        output.putInt(manifest.sealedSegments().size());
        manifest.checkpoint().ifPresent(value -> writeCheckpoint(output, value));
        for (Segment segment : manifest.sealedSegments()) {
            writeSegment(output, segment);
        }
        writeActive(output, manifest.activeWal());
        MessageDigest digest = SigningFormatSupport.sha256();
        digest.update(output.array(), 0, output.position());
        output.put(digest.digest());
        return output.array();
    }

    /* default */ static Manifest decode(byte[] encoded) throws IOException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length < FIXED_PREFIX_BYTES + ACTIVE_FIXED_BYTES + COMMITMENT_BYTES
                || encoded.length > MAX_ENCODED_BYTES) {
            throw invalid("signing manifest length is invalid");
        }
        verifyDigest(encoded);
        ByteBuffer input = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        int magic = input.getInt();
        short version = input.getShort();
        short flags = input.getShort();
        int declaredLength = input.getInt();
        long revision = input.getLong();
        long committedSequence = input.getLong();
        int checkpointPresent = Byte.toUnsignedInt(input.get());
        byte[] reserved = new byte[3];
        input.get(reserved);
        int segmentCount = input.getInt();
        if (magic != MAGIC) {
            throw invalid("signing manifest magic is invalid");
        }
        if (version != VERSION) {
            throw invalid("signing manifest version is unsupported");
        }
        if (flags != FLAGS || declaredLength != encoded.length || revision < 0L
                || committedSequence < 0L || checkpointPresent > 1 || !allZero(reserved)
                || segmentCount < 0 || segmentCount > MAX_SEGMENTS) {
            throw invalid("signing manifest header is invalid");
        }
        try {
            Optional<Checkpoint> checkpoint = checkpointPresent == 1
                    ? Optional.of(readCheckpoint(input)) : Optional.empty();
            List<Segment> segments = new ArrayList<>(segmentCount);
            for (int index = 0; index < segmentCount; index++) {
                segments.add(readSegment(input));
            }
            ActiveWal active = readActive(input);
            if (input.remaining() != COMMITMENT_BYTES) {
                throw invalid("signing manifest has trailing data");
            }
            input.position(input.limit());
            Manifest manifest = new Manifest(revision, committedSequence, checkpoint, segments, active);
            validate(manifest);
            return manifest;
        } catch (IllegalArgumentException failure) {
            throw invalid("signing manifest semantic fields are invalid");
        }
    }

    private static void validate(Manifest manifest) {
        Objects.requireNonNull(manifest, "manifest");
        if (manifest.committedRevision() < 0L || manifest.committedSequence() < 0L
                || manifest.sealedSegments().size() > MAX_SEGMENTS) {
            throw new IllegalArgumentException("signing manifest fields are invalid");
        }
        long expected = 0L;
        java.util.Set<Long> generationIdentities = new java.util.HashSet<>();
        if (manifest.checkpoint().isPresent()) {
            Checkpoint checkpoint = manifest.checkpoint().orElseThrow();
            requireLengthAndCommitment(checkpoint.length(), checkpoint.commitment());
            if (checkpoint.generationIdentity() < 0L || checkpoint.revision() < 0L
                    || checkpoint.coveredSequence() < 0L
                    || checkpoint.revision() > manifest.committedRevision()
                    || !generationIdentities.add(checkpoint.generationIdentity())
                    || !checkpoint.name().equals(checkpointName(
                            checkpoint.revision(), checkpoint.coveredSequence()))) {
                throw new IllegalArgumentException("signing checkpoint descriptor is invalid");
            }
            expected = increment(checkpoint.coveredSequence());
        }
        for (Segment segment : manifest.sealedSegments()) {
            requireLengthAndCommitment(segment.length(), segment.commitment());
            if (segment.generationIdentity() < 0L || segment.firstSequence() != expected
                    || segment.sequenceCount() <= 0L
                    || !generationIdentities.add(segment.generationIdentity())) {
                throw new IllegalArgumentException("signing segment ranges are not contiguous");
            }
            long last = lastSequence(segment.firstSequence(), segment.sequenceCount());
            if (!segment.name().equals(segmentName(segment.firstSequence(), last))) {
                throw new IllegalArgumentException("signing segment name is not canonical");
            }
            expected = increment(last);
        }
        ActiveWal active = manifest.activeWal();
        requireLengthAndCommitment(active.length(), active.commitment());
        long expectedManifestSequence = expected == 0L ? 0L : expected - 1L;
        byte[] expectedActiveHeader = SigningWalContainerCodec.encode(
                new SigningWalContainerCodec.Header(active.identity(), active.firstSequence(),
                        active.baselineRevision()));
        byte[] expectedActiveCommitment = SigningFormatSupport.sha256().digest(expectedActiveHeader);
        if (active.identity() < 0L || !generationIdentities.add(active.identity())
                || active.firstSequence() != expected
                || active.baselineRevision() != manifest.committedRevision()
                || active.length() != SigningWalContainerCodec.HEADER_BYTES
                || !MessageDigest.isEqual(active.commitment(), expectedActiveCommitment)
                || !active.name().equals(activeName(active.identity()))) {
            throw new IllegalArgumentException("active signing WAL descriptor is invalid");
        }
        if (manifest.committedSequence() != expectedManifestSequence) {
            throw new IllegalArgumentException("signing manifest committed sequence is inconsistent");
        }
    }

    private static void requireLengthAndCommitment(long length, byte[] commitment) {
        if (length <= 0L || length > MAX_FILE_BYTES || commitment.length != COMMITMENT_BYTES) {
            throw new IllegalArgumentException("signing file descriptor is invalid");
        }
    }

    private static long lastSequence(long first, long count) {
        if (first < 0L || count <= 0L) {
            throw new IllegalArgumentException("signing sequence range is invalid");
        }
        try {
            return Math.addExact(first, count - 1L);
        } catch (ArithmeticException failure) {
            throw new IllegalArgumentException("signing sequence range overflows", failure);
        }
    }

    private static long increment(long value) {
        try {
            return Math.incrementExact(value);
        } catch (ArithmeticException failure) {
            throw new IllegalArgumentException("signing sequence range overflows", failure);
        }
    }

    private static void writeCheckpoint(ByteBuffer output, Checkpoint value) {
        output.putLong(value.generationIdentity());
        output.putLong(value.revision());
        output.putLong(value.coveredSequence());
        output.putLong(value.length());
        output.put(value.commitmentInternal());
        writeName(output, value.name());
    }

    private static void writeSegment(ByteBuffer output, Segment value) {
        output.putLong(value.generationIdentity());
        output.putLong(value.firstSequence());
        output.putLong(value.sequenceCount());
        output.putLong(value.length());
        output.put(value.commitmentInternal());
        writeName(output, value.name());
    }

    private static void writeActive(ByteBuffer output, ActiveWal value) {
        output.putLong(value.identity());
        output.putLong(value.firstSequence());
        output.putLong(value.baselineRevision());
        output.putLong(value.length());
        output.put(value.commitmentInternal());
        writeName(output, value.name());
    }

    private static Checkpoint readCheckpoint(ByteBuffer input) throws IOException {
        requireRemaining(input, CHECKPOINT_FIXED_BYTES);
        return new Checkpoint(input.getLong(), input.getLong(), input.getLong(), input.getLong(),
                readCommitment(input), readName(input));
    }

    private static Segment readSegment(ByteBuffer input) throws IOException {
        requireRemaining(input, SEGMENT_FIXED_BYTES);
        return new Segment(input.getLong(), input.getLong(), input.getLong(), input.getLong(),
                readCommitment(input), readName(input));
    }

    private static ActiveWal readActive(ByteBuffer input) throws IOException {
        requireRemaining(input, ACTIVE_FIXED_BYTES);
        return new ActiveWal(input.getLong(), input.getLong(), input.getLong(), input.getLong(),
                readCommitment(input), readName(input));
    }

    private static byte[] readCommitment(ByteBuffer input) {
        byte[] commitment = new byte[COMMITMENT_BYTES];
        input.get(commitment);
        return commitment;
    }

    private static void writeName(ByteBuffer output, String name) {
        byte[] bytes = encodedName(name);
        output.putShort((short) bytes.length);
        output.put(bytes);
    }

    private static String readName(ByteBuffer input) throws IOException {
        requireRemaining(input, Short.BYTES);
        int length = Short.toUnsignedInt(input.getShort());
        if (length == 0 || length > MAX_NAME_BYTES) {
            throw invalid("signing manifest name length is invalid");
        }
        requireRemaining(input, length);
        byte[] bytes = new byte[length];
        input.get(bytes);
        String value = SigningFormatSupport.decodeUtf8(bytes);
        if (!Arrays.equals(bytes, encodedName(value))) {
            throw invalid("signing manifest name is not canonical");
        }
        return value;
    }

    private static byte[] encodedName(String name) {
        byte[] bytes = SigningFormatSupport.strictUtf8(name, MAX_NAME_BYTES);
        for (byte value : bytes) {
            int character = Byte.toUnsignedInt(value);
            if (!(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'z')
                    && character != '-' && character != '.') {
                throw new IllegalArgumentException("signing manifest name is not canonical");
            }
        }
        return bytes;
    }

    private static void requireRemaining(ByteBuffer input, int required) throws IOException {
        if (required < 0 || input.remaining() < required) {
            throw invalid("signing manifest is truncated");
        }
    }

    private static void verifyDigest(byte[] encoded) throws IOException {
        MessageDigest digest = SigningFormatSupport.sha256();
        digest.update(encoded, 0, encoded.length - COMMITMENT_BYTES);
        byte[] supplied = Arrays.copyOfRange(encoded, encoded.length - COMMITMENT_BYTES, encoded.length);
        if (!MessageDigest.isEqual(digest.digest(), supplied)) {
            throw invalid("signing manifest commitment is invalid");
        }
    }

    private static boolean allZero(byte[] bytes) {
        for (byte value : bytes) {
            if (value != 0) {
                return false;
            }
        }
        return true;
    }

    /* default */ static String checkpointName(long revision, long sequence) {
        return String.format(Locale.ROOT, "checkpoint-%020d-%020d.zec", revision, sequence);
    }

    /* default */ static String segmentName(long first, long last) {
        return String.format(Locale.ROOT, "wal-%020d-%020d.zew", first, last);
    }

    /* default */ static String activeName(long identity) {
        return String.format(Locale.ROOT, "wal-active-%020d.zew", identity);
    }

    private static IOException invalid(String diagnostic) {
        return SigningFormatSupport.invalid(diagnostic);
    }

    /* default */ record Manifest(long committedRevision, long committedSequence,
            Optional<Checkpoint> checkpoint, List<Segment> sealedSegments, ActiveWal activeWal) {
        Manifest {
            checkpoint = Objects.requireNonNull(checkpoint, "checkpoint");
            Objects.requireNonNull(sealedSegments, "sealedSegments");
            if (committedRevision < 0L || committedSequence < 0L
                    || sealedSegments.size() > MAX_SEGMENTS) {
                throw new IllegalArgumentException("signing manifest fields are invalid");
            }
            sealedSegments = List.copyOf(sealedSegments);
            Objects.requireNonNull(activeWal, "activeWal");
        }
    }

    /* default */ record Checkpoint(long generationIdentity, long revision,
            long coveredSequence, long length, byte[] commitment, String name) {
        Checkpoint {
            Objects.requireNonNull(commitment, "commitment");
            if (commitment.length != COMMITMENT_BYTES || generationIdentity < 0L || revision < 0L
                    || coveredSequence < 0L || length <= 0L || length > MAX_FILE_BYTES) {
                throw new IllegalArgumentException("signing checkpoint descriptor is invalid");
            }
            encodedName(name);
            commitment = commitment.clone();
        }

        @Override
        public byte[] commitment() {
            return commitment.clone();
        }

        private byte[] commitmentInternal() {
            return commitment;
        }
    }

    /* default */ record Segment(long generationIdentity, long firstSequence,
            long sequenceCount, long length, byte[] commitment, String name) {
        Segment {
            Objects.requireNonNull(commitment, "commitment");
            if (commitment.length != COMMITMENT_BYTES || generationIdentity < 0L || firstSequence < 0L
                    || sequenceCount <= 0L || length <= 0L || length > MAX_FILE_BYTES) {
                throw new IllegalArgumentException("signing segment descriptor is invalid");
            }
            encodedName(name);
            commitment = commitment.clone();
        }

        @Override
        public byte[] commitment() {
            return commitment.clone();
        }

        private byte[] commitmentInternal() {
            return commitment;
        }
    }

    /* default */ record ActiveWal(long identity, long firstSequence, long baselineRevision,
            long length, byte[] commitment, String name) {
        ActiveWal {
            Objects.requireNonNull(commitment, "commitment");
            if (commitment.length != COMMITMENT_BYTES || identity < 0L
                    || firstSequence < 0L || baselineRevision < 0L
                    || length <= 0L || length > MAX_FILE_BYTES) {
                throw new IllegalArgumentException("active signing WAL descriptor is invalid");
            }
            encodedName(name);
            commitment = commitment.clone();
        }

        @Override
        public byte[] commitment() {
            return commitment.clone();
        }

        private byte[] commitmentInternal() {
            return commitment;
        }
    }
}
