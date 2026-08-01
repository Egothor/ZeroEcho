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
package zeroecho.pki.impl.framework.x509;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;

/**
 * Focused incremental canonical-DER structural validator.
 *
 * <p>
 * Validation consumes exactly one object, rejects indefinite and non-minimal
 * lengths, and checks canonical primitive forms without materializing aggregate
 * content. Aggregate offsets and lengths use {@code long}. The fixed structural
 * depth is an X.509 adapter capability, not an aggregate byte or cardinality
 * limit.
 * </p>
 *
 * <p>
 * Canonical SET ordering uses two monotonic comparison readers per active,
 * fixed-bounded structure depth. Each reader moves forward only, so validation
 * is {@code O(B)} for encoded size {@code B} with auxiliary heap bounded by the
 * fixed depth and comparison-buffer size.
 * </p>
 */
public final class StreamingDerReader {

    private static final int BUFFER_BYTES = 16 * 1024;
    private static final int MAXIMUM_X509_STRUCTURE_DEPTH = 64;
    private static final int HIGH_TAG_NUMBER = 0x1f;
    private static final int CONTINUATION_BIT = 0x80;
    private static final long SHORT_LENGTH_LIMIT = 128L;

    /**
     * Validates one complete canonical DER object.
     *
     * @param content repeatable original content
     * @param cancellation cancellation signal
     * @return exact encoded length
     * @throws IOException if input fails, is malformed, non-canonical, truncated,
     *                     or has trailing data
     */
    public long validate(RepeatableContent content, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(cancellation, "cancellation");
        try (CountedInput input = new CountedInput(content.openStream());
                OrderingContext ordering = new OrderingContext(content)) {
            Header root = HeaderReader.read(input);
            readValue(input, root, 0, cancellation, ordering);
            if (input.read() >= 0) {
                throw new IOException("Trailing DER data: code=TRAILING_DER_DATA");
            }
            long length = input.position();
            if (content.length().isPresent() && length != content.length().getAsLong()) {
                throw new IOException("DER length mismatch: code=NON_CANONICAL_DER");
            }
            return length;
        }
    }

    /**
     * Validates and locates the signed portions of one certificate or CRL.
     *
     * @param content original repeatable DER
     * @param kind signed-object grammar
     * @param cancellation cancellation signal
     * @return immutable long-offset layout
     * @throws IOException if structure or canonicality is invalid
     */
    public SignedObjectLayout inspectSignedObject(RepeatableContent content, SignedObjectKind kind,
            CancellationSignal cancellation) throws IOException {
        validate(content, cancellation);
        try (CountedInput input = new CountedInput(content.openStream())) {
            Header outer = HeaderReader.read(input);
            requireSequence(outer);
            long outerEnd = Math.addExact(input.position(), outer.length());
            Header tbs = HeaderReader.read(input);
            requireSequence(tbs);
            long tbsTotalLength = tbs.encodedLength();
            AlgorithmAndKey inner = inspectTbs(content, kind, tbs, cancellation);
            skip(input, tbs.length(), cancellation);
            Header outerAlgorithm = HeaderReader.read(input);
            requireSequence(outerAlgorithm);
            skip(input, outerAlgorithm.length(), cancellation);
            Header signature = HeaderReader.read(input);
            if (!signature.universal() || signature.tagNumber() != 3 || signature.constructed()
                    || signature.length() < 1L) {
                throw new IOException("Malformed signed-object signature BIT STRING");
            }
            int unused = input.readRequired();
            if (unused != 0) {
                throw new IOException("Signed-object signature has unused bits");
            }
            long signatureOffset = input.position();
            skip(input, signature.length() - 1L, cancellation);
            if (input.position() != outerEnd || input.read() >= 0) {
                throw new IOException("Signed object has trailing data");
            }
            return new SignedObjectLayout(tbs.start(), tbsTotalLength, inner.algorithmOffset(),
                    inner.algorithmLength(), outerAlgorithm.start(), outerAlgorithm.encodedLength(),
                    inner.spkiOffset(), inner.spkiLength(), signatureOffset, signature.length() - 1L);
        }
    }

    private static AlgorithmAndKey inspectTbs(RepeatableContent content, SignedObjectKind kind, Header tbs,
            CancellationSignal cancellation) throws IOException {
        try (CountedInput input = new CountedInput(content.openStream())) {
            skip(input, tbs.valueOffset(), cancellation);
            Header child = HeaderReader.read(input);
            if (kind == SignedObjectKind.CERTIFICATE) {
                if (child.contextSpecific(0)) {
                    skip(input, child.length(), cancellation);
                    child = HeaderReader.read(input);
                }
                requireUniversal(child, 2);
                skip(input, child.length(), cancellation);
                child = HeaderReader.read(input);
            } else if (child.universal() && child.tagNumber() == 2) {
                skip(input, child.length(), cancellation);
                child = HeaderReader.read(input);
            }
            requireSequence(child);
            long algorithmOffset = child.start();
            long algorithmLength = child.encodedLength();
            if (kind == SignedObjectKind.CRL) {
                return new AlgorithmAndKey(algorithmOffset, algorithmLength, -1L, 0L);
            }
            skip(input, child.length(), cancellation);
            for (int index = 0; index < 3; index++) {
                Header field = HeaderReader.read(input);
                skip(input, field.length(), cancellation);
            }
            Header spki = HeaderReader.read(input);
            requireSequence(spki);
            return new AlgorithmAndKey(algorithmOffset, algorithmLength, spki.start(), spki.encodedLength());
        }
    }

    private static void requireSequence(Header header) throws IOException {
        requireUniversal(header, 16);
        if (!header.constructed()) {
            throw new IOException("Expected constructed DER SEQUENCE");
        }
    }

    private static void requireUniversal(Header header, int tagNumber) throws IOException {
        if (!header.universal() || header.tagNumber() != tagNumber) {
            throw new IOException("Unexpected signed-object DER field");
        }
    }

    private static void readValue(CountedInput input, Header header, int depth, CancellationSignal cancellation,
            OrderingContext ordering) throws IOException {
        if (depth >= MAXIMUM_X509_STRUCTURE_DEPTH) {
            throw new IOException("DER nesting exceeds X.509 adapter capability");
        }
        long end = Math.addExact(input.position(), header.length());
        if (header.constructed()) {
            requireConstructedForm(header);
            SetOrdering setOrdering = header.universal() && header.tagNumber() == 17
                    ? ordering.begin(depth, header.valueOffset(), cancellation)
                    : null;
            while (input.position() < end) {
                cancellation.throwIfCancelled();
                Header child = HeaderReader.read(input);
                long childEnd = Math.addExact(input.position(), child.length());
                if (childEnd > end) {
                    throw new IOException("DER child exceeds parent: code=MALFORMED_SIGNED_OBJECT");
                }
                readValue(input, child, depth + 1, cancellation, ordering);
                if (setOrdering != null && setOrdering.accept(child.encodedLength(), cancellation) > 0) {
                    throw new IOException("Non-canonical DER SET ordering: code=NON_CANONICAL_DER");
                }
            }
            if (setOrdering != null) {
                setOrdering.finish(cancellation);
            }
        } else {
            requirePrimitiveForm(header);
            PrimitiveReader.read(input, header, cancellation);
        }
        if (input.position() != end) {
            throw new IOException("DER value length mismatch: code=MALFORMED_SIGNED_OBJECT");
        }
    }

    private static void requireConstructedForm(Header header) throws IOException {
        if (header.universal() && header.tagNumber() != 16 && header.tagNumber() != 17) {
            throw new IOException("Constructed primitive is not canonical DER");
        }
    }

    private static void requirePrimitiveForm(Header header) throws IOException {
        if (header.universal() && (header.tagNumber() == 16 || header.tagNumber() == 17)) {
            throw new IOException("Primitive container is not canonical DER");
        }
    }

    private static void skip(CountedInput input, long length, CancellationSignal cancellation) throws IOException {
        byte[] buffer = new byte[BUFFER_BYTES];
        long remaining = length;
        while (remaining != 0L) {
            cancellation.throwIfCancelled();
            int read = input.read(buffer, 0, (int) Math.min(buffer.length, remaining));
            if (read < 0) {
                throw new IOException("Truncated DER value");
            }
            if (read == 0) {
                input.readRequired();
                remaining--;
            } else {
                remaining -= read;
            }
        }
    }

    /**
     * Supported signed-object grammar.
     */
    public enum SignedObjectKind {
        /** X.509 Certificate. */
        CERTIFICATE,
        /** X.509 CertificateList (CRL). */
        CRL
    }

    /**
     * Exact offsets into the validated original DER.
     *
     * @param tbsOffset complete TBS TLV offset
     * @param tbsLength complete TBS TLV length
     * @param tbsAlgorithmOffset TBS AlgorithmIdentifier TLV offset
     * @param tbsAlgorithmLength TBS AlgorithmIdentifier TLV length
     * @param outerAlgorithmOffset outer AlgorithmIdentifier TLV offset
     * @param outerAlgorithmLength outer AlgorithmIdentifier TLV length
     * @param subjectPublicKeyInfoOffset SPKI TLV offset, or {@code -1} for CRLs
     * @param subjectPublicKeyInfoLength SPKI TLV length, or zero for CRLs
     * @param signatureOffset signature octets offset
     * @param signatureLength signature octets length
     */
    public record SignedObjectLayout(long tbsOffset, long tbsLength, long tbsAlgorithmOffset,
            long tbsAlgorithmLength, long outerAlgorithmOffset, long outerAlgorithmLength,
            long subjectPublicKeyInfoOffset, long subjectPublicKeyInfoLength, long signatureOffset,
            long signatureLength) {
    }

    private record AlgorithmAndKey(long algorithmOffset, long algorithmLength, long spkiOffset, long spkiLength) {
    }

    private record Header(int firstTag, int tagNumber, long length, long start, long valueOffset) {
        private boolean constructed() {
            return (firstTag & 0x20) != 0;
        }

        private boolean universal() {
            return (firstTag & 0xc0) == 0;
        }

        private boolean contextSpecific(int expectedTag) {
            return (firstTag & 0xc0) == 0x80 && tagNumber == expectedTag;
        }

        private long encodedLength() {
            return Math.addExact(valueOffset - start, length);
        }
    }

    /** Canonical DER tag and length decoder. */
    private static final class HeaderReader {
        private static Header read(CountedInput input) throws IOException {
            long start = input.position();
            int firstTag = input.readRequired();
            if (firstTag == 0) {
                throw new IOException("DER end-of-contents is forbidden");
            }
            int tagNumber = readTagNumber(input, firstTag);
            long length = readLength(input);
            return new Header(firstTag, tagNumber, length, start, input.position());
        }

        private static int readTagNumber(CountedInput input, int firstTag) throws IOException {
            int tagNumber = firstTag & HIGH_TAG_NUMBER;
            if (tagNumber == HIGH_TAG_NUMBER) {
                int octet = input.readRequired();
                if ((octet & 0x7f) == 0) {
                    throw new IOException("Non-minimal DER high tag");
                }
                while ((octet & CONTINUATION_BIT) != 0) {
                    octet = input.readRequired();
                }
                tagNumber = -1;
            }
            return tagNumber;
        }

        private static long readLength(CountedInput input) throws IOException {
            int firstLength = input.readRequired();
            if (firstLength < CONTINUATION_BIT) {
                return firstLength;
            }
            int octets = firstLength & 0x7f;
            if (octets == 0) {
                throw new IOException("Indefinite DER length: code=NON_CANONICAL_DER");
            }
            if (octets > Long.BYTES) {
                throw new IOException("DER length is not representable");
            }
            int first = input.readRequired();
            if (first == 0) {
                throw new IOException("Non-minimal DER length: code=NON_CANONICAL_DER");
            }
            long length = first;
            for (int index = 1; index < octets; index++) {
                if (length > (Long.MAX_VALUE >>> Byte.SIZE)) {
                    throw new IOException("DER length overflow: code=CONTENT_LENGTH_OVERFLOW");
                }
                length = (length << Byte.SIZE) | input.readRequired();
            }
            if (length < SHORT_LENGTH_LIMIT) {
                throw new IOException("Non-minimal DER length: code=NON_CANONICAL_DER");
            }
            return length;
        }
    }

    /** Fixed-depth owner of monotonic comparison streams for DER SET values. */
    private static final class OrderingContext implements AutoCloseable {
        private final RepeatableContent content;
        private final SetOrdering[] levels = new SetOrdering[MAXIMUM_X509_STRUCTURE_DEPTH];

        private OrderingContext(RepeatableContent content) {
            this.content = content;
        }

        private SetOrdering begin(int depth, long valueOffset, CancellationSignal cancellation) throws IOException {
            SetOrdering ordering = levels[depth];
            if (ordering == null) {
                ordering = new SetOrdering(content);
                levels[depth] = ordering;
            }
            ordering.begin(valueOffset, cancellation);
            return ordering;
        }

        @Override
        public void close() throws IOException {
            IOException failure = null;
            for (SetOrdering ordering : levels) {
                if (ordering == null) {
                    continue;
                }
                try {
                    ordering.closeStreams();
                } catch (IOException exception) {
                    if (failure == null) {
                        failure = exception;
                    } else {
                        failure.addSuppressed(exception);
                    }
                }
            }
            if (failure != null) {
                throw failure;
            }
        }
    }

    /** Adjacent-child comparator whose two source passes only move forward. */
    private static final class SetOrdering {
        private static final long NO_PREVIOUS_VALUE = -1L;

        private final CountedInput left;
        private final CountedInput right;
        private final byte[] leftBuffer = new byte[BUFFER_BYTES];
        private final byte[] rightBuffer = new byte[BUFFER_BYTES];
        private long previousLength = NO_PREVIOUS_VALUE;

        private SetOrdering(RepeatableContent content) throws IOException {
            left = new CountedInput(content.openStream());
            try {
                right = new CountedInput(content.openStream());
            } catch (IOException exception) {
                left.close();
                throw exception;
            }
        }

        private void begin(long valueOffset, CancellationSignal cancellation) throws IOException {
            advanceTo(left, valueOffset, leftBuffer, cancellation);
            advanceTo(right, valueOffset, rightBuffer, cancellation);
            previousLength = NO_PREVIOUS_VALUE;
        }

        private int accept(long currentLength, CancellationSignal cancellation) throws IOException {
            if (previousLength == NO_PREVIOUS_VALUE) {
                skipWithBuffer(right, currentLength, rightBuffer, cancellation);
                previousLength = currentLength;
                return 0;
            }
            int comparison = compare(previousLength, currentLength, cancellation);
            previousLength = currentLength;
            return comparison;
        }

        private void finish(CancellationSignal cancellation) throws IOException {
            if (previousLength != NO_PREVIOUS_VALUE) {
                skipWithBuffer(left, previousLength, leftBuffer, cancellation);
            }
        }

        private int compare(long leftLength, long rightLength, CancellationSignal cancellation) throws IOException {
            long common = Math.min(leftLength, rightLength);
            int comparison = 0;
            long remaining = common;
            while (remaining != 0L) {
                cancellation.throwIfCancelled();
                int count = (int) Math.min(BUFFER_BYTES, remaining);
                readExactly(left, leftBuffer, count);
                readExactly(right, rightBuffer, count);
                if (comparison == 0) {
                    comparison = compareBuffers(leftBuffer, rightBuffer, count);
                }
                remaining -= count;
            }
            skipWithBuffer(left, leftLength - common, leftBuffer, cancellation);
            skipWithBuffer(right, rightLength - common, rightBuffer, cancellation);
            return comparison == 0 ? Long.compare(leftLength, rightLength) : comparison;
        }

        private void closeStreams() throws IOException {
            IOException failure = null;
            try {
                left.close();
            } catch (IOException exception) {
                failure = exception;
            }
            try {
                right.close();
            } catch (IOException exception) {
                if (failure == null) {
                    failure = exception;
                } else {
                    failure.addSuppressed(exception);
                }
            }
            if (failure != null) {
                throw failure;
            }
        }

        private static void advanceTo(CountedInput input, long position, byte[] buffer,
                CancellationSignal cancellation) throws IOException {
            if (input.position() > position) {
                throw new IOException("DER SET comparison stream moved backward");
            }
            skipWithBuffer(input, position - input.position(), buffer, cancellation);
        }

        private static void skipWithBuffer(InputStream input, long length, byte[] buffer,
                CancellationSignal cancellation) throws IOException {
            long remaining = length;
            while (remaining != 0L) {
                cancellation.throwIfCancelled();
                int count = (int) Math.min(buffer.length, remaining);
                readExactly(input, buffer, count);
                remaining -= count;
            }
        }

        private static void readExactly(InputStream input, byte[] buffer, int length) throws IOException {
            int offset = 0;
            while (offset != length) {
                int count = input.read(buffer, offset, length - offset);
                if (count < 0) {
                    throw new IOException("Truncated DER value");
                }
                if (count == 0) {
                    int value = input.read();
                    if (value < 0) {
                        throw new IOException("Truncated DER value");
                    }
                    buffer[offset] = (byte) value;
                    offset++;
                } else {
                    offset += count;
                }
            }
        }

        private static int compareBuffers(byte[] left, byte[] right, int length) {
            for (int index = 0; index < length; index++) {
                int comparison = Integer.compare(Byte.toUnsignedInt(left[index]), Byte.toUnsignedInt(right[index]));
                if (comparison != 0) {
                    return comparison;
                }
            }
            return 0;
        }
    }

    /**
     * Input wrapper retaining an overflow-checked long byte position.
     */
    private static final class CountedInput extends InputStream {
        private final InputStream delegate;
        private long position;

        private CountedInput(InputStream delegate) {
            super();
            this.delegate = delegate;
        }

        @Override
        public int read() throws IOException {
            int value = delegate.read();
            if (value >= 0) {
                position = Math.addExact(position, 1L);
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            int count = delegate.read(bytes, offset, length);
            if (count > 0) {
                position = Math.addExact(position, count);
            }
            return count;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        private int readRequired() throws IOException {
            int value = read();
            if (value < 0) {
                throw new IOException("Truncated DER object");
            }
            return value;
        }

        private long position() {
            return position;
        }
    }

    /**
     * Canonical validation for primitive DER values.
     */
    private static final class PrimitiveReader {
        private static final long EMPTY_LENGTH = 0L;
        private static final long SINGLE_OCTET_LENGTH = 1L;

        private static void read(CountedInput input, Header header, CancellationSignal cancellation)
                throws IOException {
            if (!header.universal()) {
                skip(input, header.length(), cancellation);
                return;
            }
            switch (header.tagNumber()) {
                case 1 -> readBoolean(input, header.length());
                case 2 -> readInteger(input, header.length(), cancellation);
                case 3 -> readBitString(input, header.length(), cancellation);
                case 5 -> readNull(header.length());
                case 6 -> readOid(input, header.length(), cancellation);
                default -> skip(input, header.length(), cancellation);
            }
        }

        private static void readBoolean(CountedInput input, long length) throws IOException {
            if (length != SINGLE_OCTET_LENGTH) {
                throw new IOException("Malformed DER BOOLEAN");
            }
            int value = input.readRequired();
            if (value != 0 && value != 0xff) {
                throw new IOException("Non-canonical DER BOOLEAN");
            }
        }

        private static void readInteger(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            if (length == EMPTY_LENGTH) {
                throw new IOException("Malformed DER INTEGER");
            }
            int first = input.readRequired();
            if (length > SINGLE_OCTET_LENGTH) {
                int second = input.readRequired();
                if ((first == 0 && (second & CONTINUATION_BIT) == 0)
                        || (first == 0xff && (second & CONTINUATION_BIT) != 0)) {
                    throw new IOException("Non-canonical DER INTEGER");
                }
                skip(input, length - 2L, cancellation);
            }
        }

        private static void readBitString(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            if (length == EMPTY_LENGTH) {
                throw new IOException("Malformed DER BIT STRING");
            }
            int unused = input.readRequired();
            if (unused > 7 || (length == SINGLE_OCTET_LENGTH && unused != 0)) {
                throw new IOException("Malformed DER BIT STRING");
            }
            long octets = length - SINGLE_OCTET_LENGTH;
            if (octets == EMPTY_LENGTH) {
                return;
            }
            int last = 0;
            for (long index = 0L; index < octets; index++) {
                cancellation.throwIfCancelled();
                last = input.readRequired();
            }
            if (unused != 0 && (last & ((1 << unused) - 1)) != 0) {
                throw new IOException("Non-canonical DER BIT STRING");
            }
        }

        private static void readNull(long length) throws IOException {
            if (length != EMPTY_LENGTH) {
                throw new IOException("Malformed DER NULL");
            }
        }

        private static void readOid(CountedInput input, long length, CancellationSignal cancellation)
                throws IOException {
            if (length == EMPTY_LENGTH) {
                throw new IOException("Malformed DER OID");
            }
            boolean atComponentStart = true;
            for (long index = 0L; index < length; index++) {
                cancellation.throwIfCancelled();
                int octet = input.readRequired();
                if (atComponentStart && octet == CONTINUATION_BIT) {
                    throw new IOException("Non-canonical DER OID");
                }
                atComponentStart = (octet & CONTINUATION_BIT) == 0;
            }
            if (!atComponentStart) {
                throw new IOException("Truncated DER OID");
            }
        }
    }
}
