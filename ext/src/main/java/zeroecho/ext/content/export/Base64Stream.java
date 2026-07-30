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
package zeroecho.ext.content.export;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import java.util.Base64.Encoder;

/**
 * A streaming {@link InputStream} that encodes binary input data into Base64
 * format with optional line prefixes and suffixes for each encoded line.
 *
 * <p>
 * This class is designed for script-friendly output formatting, such as
 * generating platform-specific batch or shell script lines where each line
 * might begin with a command (e.g., {@code echo }) and end with a
 * platform-specific line terminator (e.g., {@code \n} for UNIX-like systems or
 * {@code \r\n} for Windows).
 * </p>
 *
 * <p>
 * It supports chunked streaming and avoids holding the entire Base64-encoded
 * content in memory, making it suitable for large binary inputs. Lines are
 * split according to the specified maximum line length and are composed as
 * follows:
 * </p>
 *
 * <pre>
 *     [prefix][base64-encoded data][suffix]
 * </pre>
 *
 * <p>
 * If a suffix is defined, the actual Base64 data per line will be truncated to
 * {@code lineLength - suffix.length} characters to ensure total line length
 * does not exceed {@code lineLength}.
 * </p>
 *
 * <p>
 * This stream does not automatically insert newlines between lines unless
 * explicitly provided via the {@code suffix} argument (e.g.,
 * {@code "\n".getBytes()}).
 * </p>
 *
 * <p>
 * <strong>Usage example:</strong>
 * </p>
 *
 * <pre>{@code
 * InputStream source = new FileInputStream("input.bin");
 * InputStream encoded = new Base64Stream(
 *     source,
 *     "echo ".getBytes(StandardCharsets.UTF_8),
 *     76,
 *     "\n".getBytes(StandardCharsets.UTF_8)
 * );
 * encoded.transferTo(System.out);
 * }</pre>
 *
 * @author Leo Galambos
 */
public class Base64Stream extends InputStream {

    private final InputStream source;
    private InputStream in;
    private InputStream prefix;
    private InputStream suffix;
    private final Encoder base64;
    private int pos;
    private final int lineLength;
    private int lineBreak;

    private InputStream is = nullInputStream(); // NOPMD
    private int breakPos; // NOPMD
    private boolean closed;

    private final static int TRIPLES_INPUT = 1000;

    /**
     * Constructs a new {@code Base64Stream}.
     *
     * @param source     the raw binary input stream to be Base64 encoded
     * @param linePrefix optional prefix to prepend at the beginning of each line
     *                   (e.g., {@code "echo "}); can be {@code null} for no prefix
     * @param lineLength the total maximum length of each output line, including any
     *                   prefix and suffix
     * @param lineSuffix optional suffix to append at the end of each line (e.g.,
     *                   newline); can be {@code null}
     */
    public Base64Stream(InputStream source, byte[] linePrefix, int lineLength, byte[] lineSuffix) {
        super();

        this.source = source;
        this.lineLength = lineLength;
        in = nullInputStream();
        base64 = Base64.getEncoder();
        if (linePrefix != null) {
            prefix = new ByteArrayInputStream(linePrefix);
        }
        if (lineSuffix != null) {
            suffix = new ByteArrayInputStream(lineSuffix);
        }
        lineBreak = lineLength - ((lineSuffix == null) ? 0 : lineSuffix.length);
    }

    @Override
    public int read() throws IOException {
        byte[] result = { 0 };
        int count = read(result, 0, 1);
        return (count == 0) ? -1 : result[0] & 0xff;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (pos == lineLength) {
            pos = 0;
        }

        if (pos == 0 && prefix != null) {
            prefix.reset();
            breakPos = Integer.MAX_VALUE;
            is = prefix;
        } else {
            if (pos == lineBreak && suffix != null && !closed) {
                suffix.reset();
                breakPos = Integer.MAX_VALUE;
                is = suffix;
            } else {
                if (in.available() == 0) {
                    ensureData();
                }
                breakPos = lineBreak;
                is = in;
            }
        }

        int l = Math.min(Math.min(is.available(), len), breakPos - pos);
        pos += l;
        return is.read(b, off, l);
    }

    /**
     * Reads the next block of raw bytes from the source and encodes them into
     * Base64. Handles stream exhaustion and final line suffix if applicable.
     */
    private void ensureData() throws IOException {
        byte[] buf = source.readNBytes(3 * TRIPLES_INPUT);

        if (buf.length == 0 && suffix != null && !closed) {
            System.out.println("suffix");

            closed = true;
            suffix.reset();
            breakPos = lineBreak = Integer.MAX_VALUE;
            in = suffix;
            return;
        }

        if (buf.length == 3 * TRIPLES_INPUT) {
            in = new ByteArrayInputStream(base64.withoutPadding().encode(buf));
        } else {
            in = new ByteArrayInputStream(base64.encode(buf));
        }
    }
}
