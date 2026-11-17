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

package zeroecho.pki.impl.framework.x509;

import zeroecho.core.io.CancellationSignal;
import zeroecho.core.io.RepeatableContent;
import zeroecho.pki.impl.framework.x509.bc.BcX509AlgorithmAdapter;
import zeroecho.pkix.Pkix;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Streaming transforms for the explicitly qualified BC 1.86 alternative CRL
 * transcript profile. The native algorithm and alternative signature value are
 * excluded from alternative input; no outer signed-object wrapper is introduced.
 * Work is O(B) with a constant number of forward slices and bounded signature/header
 * buffers. Sources are immutable and borrowed; outputs and opened streams are owned
 * by their callers. This utility grants no signing or verification authority.
 */
public final class StreamingCrlAlternativeSignature {
    private StreamingCrlAlternativeSignature() { }

    /**
     * Streams final native TBS from an exact validated alternative transcript.
     * Restores the native algorithm after v2 and appends the actual noncritical
     * alternative signature value. Only affected enclosing DER lengths change.
     * @param alternativeTbs immutable borrowed alternative transcript
     * @param nativeAlgorithm captured native signature AlgorithmIdentifier
     * @param alternativeSignature nonempty external signature, at most 1 MiB
     * @param output caller-owned destination, neither flushed nor closed
     * @param cancellation cooperative streaming cancellation
     * @return complete emitted native TBS length
     * @throws IOException if the transcript, bounded fields, streaming or cancellation fails
     * @throws ArithmeticException if aggregate DER length is not representable as a long
     * @throws NullPointerException if {@code alternativeSignature} is null
     */
    public static long completeTbs(RepeatableContent alternativeTbs, X509AlgorithmIdentifier nativeAlgorithm,
            byte[] alternativeSignature, OutputStream output, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(alternativeSignature, "alternativeSignature");
        if (alternativeSignature.length == 0 || alternativeSignature.length > 1024 * 1024) {
            throw new IOException("Alternative CRL signature exceeds its bounded profile");
        }
        StreamingDerReader.CrlAlternativeTbsLayout layout =
                new StreamingDerReader().inspectAlternativeCrlTbs(alternativeTbs, cancellation);
        byte[] algorithm = Pkix.encodeAlgorithmIdentifier(BcX509AlgorithmAdapter.toLib(nativeAlgorithm));
        if (algorithm.length > 16 * 1024) {
            throw new IOException("CRL algorithm exceeds header bound");
        }
        byte[] signature = tlv(0x30, concatenate(new byte[]{6, 3, 0x55, 0x1d, 0x4a},
                tlv(4, tlv(3, concatenate(new byte[]{0}, alternativeSignature)))));
        long extensionBytes = Math.addExact(layout.extensionsContentLength(), signature.length);
        long extensionSequence = StreamingDerWriter.encodedLength(extensionBytes);
        long explicit = StreamingDerWriter.encodedLength(extensionSequence);
        long body = Math.addExact(Math.addExact(layout.fieldsLength(), algorithm.length), explicit);
        List<Part> parts = List.of(bytes(header(0x30, body)), slice(layout.fieldsOffset(), 3), bytes(algorithm),
                slice(Math.addExact(layout.fieldsOffset(), 3), layout.fieldsLength() - 3),
                bytes(header(0xa0, extensionSequence)), bytes(header(0x30, extensionBytes)),
                slice(layout.extensionsContentOffset(), layout.extensionsContentLength()), bytes(signature));
        long expected = StreamingDerWriter.encodedLength(body);
        try (InputStream stream = new PartsInputStream(alternativeTbs.openStream(), parts, cancellation)) {
            if (StreamingDerWriter.copy(stream, output, cancellation) != expected) {
                throw new IOException("Hybrid CRL completion length mismatch");
            }
        }
        return expected;
    }

    /**
     * Returns a borrowed immutable view of the alternative transcript of a CRL.
     * Structural validation happens before return. Each opened stream owns one
     * fresh source reader, but closing the view never closes the original content.
     * The caller must retain the source unchanged for the view's lifetime.
     * @param completeSignedCrl complete immutable borrowed CRL DER
     * @param cancellation cancellation applied during inspection and subsequent reads
     * @return repeatable known-length view excluding only native algorithm and alternative value
     * @throws IOException if CRL profile syntax or bounded headers are invalid
     * @throws ArithmeticException if aggregate DER length is not representable as a long
     */
    public static RepeatableContent alternativeTbs(RepeatableContent completeSignedCrl,
            CancellationSignal cancellation) throws IOException {
        StreamingDerReader.AlternativeCrlLayout layout =
                new StreamingDerReader().inspectAlternativeCrl(completeSignedCrl, cancellation);
        StreamingDerReader.SignedObjectLayout signed = layout.semantic().layout();
        long prefix = signed.tbsAlgorithmOffset() - layout.fieldsOffset();
        long tailOffset = Math.addExact(signed.tbsAlgorithmOffset(), signed.tbsAlgorithmLength());
        long tailLength = Math.addExact(layout.fieldsOffset(), layout.fieldsLength()) - tailOffset;
        long extensionBytes = layout.extensionsContentLength() - layout.alternativeValueExtensionLength();
        long extensionSequence = StreamingDerWriter.encodedLength(extensionBytes);
        long explicit = StreamingDerWriter.encodedLength(extensionSequence);
        long body = Math.addExact(Math.addExact(prefix, tailLength), explicit);
        List<Part> parts = List.of(bytes(header(0x30, body)), slice(layout.fieldsOffset(), prefix),
                slice(tailOffset, tailLength), bytes(header(0xa0, extensionSequence)),
                bytes(header(0x30, extensionBytes)), slice(layout.extensionsContentOffset(), extensionBytes));
        long length = StreamingDerWriter.encodedLength(body);
        return new RepeatableContent() {
            @Override
            public InputStream openStream() throws IOException {
                cancellation.throwIfCancelled();
                return new PartsInputStream(completeSignedCrl.openStream(), parts, cancellation);
            }

            @Override
            public OptionalLong length() {
                return OptionalLong.of(length);
            }

            @Override
            public String contentId() {
                return completeSignedCrl.contentId() + ":crl-alt-bc186-v1";
            }

            @Override
            public void close() {
                /* Source custody remains with its owner. */
            }
        };
    }

    private static byte[] header(int tag, long length) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        StreamingDerWriter.writeTagAndLength(output, tag, length);
        return output.toByteArray();
    }

    private static byte[] tlv(int tag, byte[] value) throws IOException {
        return concatenate(header(tag, value.length), value);
    }

    private static byte[] concatenate(byte[] left, byte[] right) {
        byte[] result = java.util.Arrays.copyOf(left, Math.addExact(left.length, right.length));
        System.arraycopy(right, 0, result, left.length, right.length);
        return result;
    }

    private static Part bytes(byte[] value) { return new Part(value, 0, value.length); }
    private static Part slice(long offset, long length) { return new Part(null, offset, length); }
    private record Part(byte[] bytes, long offset, long length) { }

    /** Forward-only reader that interleaves immutable headers with borrowed source slices. */
    private static final class PartsInputStream extends InputStream {
        private final InputStream source;
        private final List<Part> parts;
        private final CancellationSignal cancellation;
        private final byte[] skipBuffer = new byte[16 * 1024];
        private long sourcePosition;
        private int index;
        private long used;
        private boolean closed;

        private PartsInputStream(InputStream source, List<Part> parts, CancellationSignal cancellation) {
            super();
            this.source = source;
            this.parts = parts;
            this.cancellation = cancellation;
        }

        /**
         * {@inheritDoc}
         */
        @Override public int read() throws IOException {
            byte[] single = new byte[1];
            return read(single, 0, 1) < 0 ? -1 : single[0] & 0xff;
        }

        /**
         * {@inheritDoc}
         */
        @Override public int read(byte[] buffer, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, buffer.length);
            if (closed) { throw new IOException("Alternative CRL view stream is closed"); }
            if (length == 0) { return 0; }
            cancellation.throwIfCancelled();
            while (index < parts.size()) {
                Part part = parts.get(index);
                if (used == part.length()) { index++; used = 0; continue; }
                int count = (int) Math.min(length, part.length() - used);
                if (part.bytes() != null) {
                    System.arraycopy(part.bytes(), Math.toIntExact(used), buffer, offset, count);
                } else {
                    position(Math.addExact(part.offset(), used));
                    count = source.read(buffer, offset, count);
                    if (count < 0) { throw new IOException("Truncated alternative CRL source"); }

                    sourcePosition = Math.addExact(sourcePosition, count);
                }
                if (count != 0) {
                    used = Math.addExact(used, count);
                    return count;
                }
            }
            return -1;
        }

        private void position(long target) throws IOException {
            if (target < sourcePosition) {
                throw new IOException("Alternative CRL slices are not forward ordered");
            }
            while (sourcePosition < target) {
                cancellation.throwIfCancelled();
                int count = source.read(skipBuffer, 0, (int) Math.min(skipBuffer.length, target - sourcePosition));
                if (count < 0) { throw new IOException("Truncated alternative CRL slice"); }
                sourcePosition = Math.addExact(sourcePosition, count);
            }
        }

        /**
         * {@inheritDoc}
         */
        @Override public void close() throws IOException {
            if (!closed) { closed = true; source.close(); }
        }
    }
}
