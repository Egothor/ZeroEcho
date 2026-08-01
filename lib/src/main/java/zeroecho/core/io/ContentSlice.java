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
package zeroecho.core.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Immutable repeatable bounded view over another repeatable content source.
 *
 * <p>
 * A slice opens a fresh source pass and skips incrementally; it never copies the
 * represented bytes. Closing the slice does not close its source because source
 * ownership remains with the creator.
 * </p>
 */
public final class ContentSlice implements RepeatableContent {

    private static final long EMPTY_LENGTH = 0L;
    private final RepeatableContent source;
    private final long offset;
    private final long length;
    private final String contentId;

    /**
     * Creates a repeatable slice.
     *
     * @param source repeatable source
     * @param offset non-negative source offset
     * @param length non-negative slice length
     * @throws IllegalArgumentException if a range is negative or exceeds a known
     *                                  source length
     */
    public ContentSlice(RepeatableContent source, long offset, long length) {
        this.source = Objects.requireNonNull(source, "source");
        if (offset < 0L || length < 0L) {
            throw new IllegalArgumentException("Content slice range must not be negative");
        }
        long end = Math.addExact(offset, length);
        OptionalLong sourceLength = source.length();
        if (sourceLength.isPresent() && end > sourceLength.getAsLong()) {
            throw new IllegalArgumentException("Content slice exceeds source");
        }
        this.offset = offset;
        this.length = length;
        this.contentId = source.contentId() + "#slice:" + offset + ':' + length;
    }

    @Override
    public InputStream openStream() throws IOException {
        InputStream input = source.openStream();
        try {
            skipExactly(input, offset);
            return new LimitedInputStream(input, length);
        } catch (IOException failure) {
            input.close();
            throw failure;
        }
    }

    @Override
    public OptionalLong length() {
        return OptionalLong.of(length);
    }

    @Override
    public String contentId() {
        return contentId;
    }

    @Override
    public void close() {
        // Source ownership remains with the creator.
    }

    private static void skipExactly(InputStream input, long count) throws IOException {
        long remaining = count;
        while (remaining != EMPTY_LENGTH) {
            long skipped = input.skip(remaining);
            if (skipped > EMPTY_LENGTH) {
                remaining -= skipped;
            } else if (input.read() < 0) {
                throw new IOException("Content slice source is truncated");
            } else {
                remaining--;
            }
        }
    }

    /** Exact-length stream view that fails when its underlying source truncates. */
    private static final class LimitedInputStream extends FilterInputStream {
        private long remaining;

        private LimitedInputStream(InputStream input, long remaining) {
            super(input);
            this.remaining = remaining;
        }

        @Override
        public int read() throws IOException {
            if (remaining == EMPTY_LENGTH) {
                return -1;
            }
            int value = super.read();
            if (value < 0) {
                throw new IOException("Content slice source is truncated");
            }
            remaining--;
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int count) throws IOException {
            Objects.checkFromIndexSize(offset, count, bytes.length);
            if (remaining == EMPTY_LENGTH) {
                return -1;
            }
            int requested = (int) Math.min(remaining, count);
            int read = super.read(bytes, offset, requested);
            if (read < 0) {
                throw new IOException("Content slice source is truncated");
            }
            remaining -= read;
            return read;
        }
    }
}
