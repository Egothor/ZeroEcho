/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.sdk.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Objects;

/**
 * An abstract adapter that converts an {@link OutputStream}-based
 * transformation (such as encryption or compression) into an
 * {@link InputStream}-based one. This class reads data from a given
 * {@link InputStream} (the {@code previousInput}), processes it through a
 * transformation {@link OutputStream} (e.g., encryption, compression), and
 * exposes the transformed data via the standard {@link InputStream} API.
 * <p>
 * Subclasses must initialize the {@code transformationOut} field with a proper
 * {@link OutputStream} that writes transformed data into the internal buffer
 * ({@code baos}). This initialization must be done <strong>after construction
 * and before any read operation</strong>, via a subclass- specific method such
 * as an <code>initialize(...)</code> method.
 * </p>
 *
 * <h2>Subclass Contract</h2>
 * <ul>
 * <li>Set {@code transformationOut} to a valid {@link OutputStream} that writes
 * to {@code baos}.</li>
 * <li>Do <em>not</em> call virtual methods like initialization from
 * constructors.</li>
 * <li>Call the initialization method before performing any reads.</li>
 * </ul>
 *
 * @author Leo Galambos
 */
public abstract class OutputToInputStreamAdapter extends InputStream {
    /**
     * Default buffer size in bytes. Typically set to 8 KB (8 * 1024 bytes).
     */
    protected static final int DEFAULT_BUF_SIZE = 8 * 1024;
    /**
     * Buffer size in bytes used by this instance. Initialized during object
     * construction and remains constant.
     */
    protected final int BUF_SIZE;

    /**
     * The original input stream containing untransformed data.
     */
    protected final InputStream previousInput;

    /**
     * A buffer holding transformed data.
     */
    protected ByteArrayOutputStream baos;

    /**
     * The output stream performing transformation and writing to {@code baos}. Must
     * be initialized by subclasses before use.
     */
    protected OutputStream transformationOut;
    /**
     * Input stream initialized to a no-op {@code InputStream} that contains no
     * data.
     * <p>
     * This stream is set to {@link InputStream#nullInputStream()}, which is a
     * convenient way to avoid {@code null} values while providing a valid,
     * non-functional stream. Useful as a default placeholder until a real stream is
     * assigned.
     * </p>
     */
    private InputStream bais = nullInputStream();

    /**
     * Constructs a new adapter wrapping the specified input stream with a given
     * buffer size for transformation output.
     *
     * @param previousInput The input stream to read untransformed data from.
     * @param bufSize       The buffer size for the transformation output buffer.
     */
    public OutputToInputStreamAdapter(final InputStream previousInput, final int bufSize) {
        super();

        Objects.requireNonNull(previousInput, "input stream must not be null");

        this.previousInput = previousInput;
        this.BUF_SIZE = bufSize;
        baos = new ByteArrayOutputStream(BUF_SIZE);
    }

    /**
     * Constructs a new adapter wrapping the specified input stream using the
     * default buffer size.
     *
     * @param previousInput The input stream to read untransformed data from.
     */
    public OutputToInputStreamAdapter(final InputStream previousInput) {
        this(previousInput, DEFAULT_BUF_SIZE);
    }

    @Override
    public int read() throws IOException {
        ensureData();
        return bais.read();
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        ensureData();
        return bais.read(b, off, len);
    }

    @Override
    public void close() throws IOException {
        previousInput.close();
    }

    /**
     * Reads untransformed data from {@code previousInput}, writes it to
     * {@code transformationOut} for processing, and buffers the transformed data in
     * {@code baos} for reading.
     *
     * @throws IOException If an I/O error occurs during reading or transformation.
     */
    private void ensureData() throws IOException {
        if (bais.available() > 0 || baos == null) {
            return;
        }

        bais = null; // NOPMD

        final byte[] chunk = previousInput.readNBytes(BUF_SIZE);
        if (chunk.length == 0) {
            transformationOut.close();
            final byte[] finalBytes = baos.toByteArray();
            bais = new ByteArrayInputStream(finalBytes);
            baos = null;
            return;
        } else {
            transformationOut.write(chunk);
        }

        final byte[] chunkBytes = baos.toByteArray();
        bais = new ByteArrayInputStream(chunkBytes);
        baos.reset();
    }
}
