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
package zeroecho.sdk.content.builtin;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * An implementation of {@link PlainContent} that encapsulates a byte array.
 * 
 * Provides read-only access to the content through an {@link InputStream}
 * backed by the internal byte buffer.
 * 
 * This class represents the start of a {@link DataContent} processing chain,
 * thus it does not accept input from preceding content.
 * 
 * @author Leo Galambos
 */
public class PlainBytes implements PlainContent {
    /**
     * Logger instance for the {@code PlainBytes} class used to log runtime
     * information, warnings, or errors. It is statically initialized with the class
     * name to ensure consistent logging context throughout the class.
     */
    private static final Logger LOG = Logger.getLogger(PlainBytes.class.getName());
    /**
     * Byte array buffer that holds the raw data managed by this instance.
     */
    protected final byte[] buffer;

    /**
     * Constructs a new {@code PlainBytes} instance by copying the provided byte
     * array.
     *
     * @param buffer the byte array to wrap
     */
    public PlainBytes(final byte[] buffer) {
        Objects.requireNonNull(buffer, "PlainBytes cannot operate with null buffer");

        this.buffer = Arrays.copyOf(buffer, buffer.length);
    }

    /**
     * Constructs a new {@code PlainBytes} instance with a buffer of the specified
     * length.
     *
     * @param length the size of the internal byte buffer to allocate
     * @throws NegativeArraySizeException if {@code length} is negative
     */
    protected PlainBytes(final int length) {
        this.buffer = new byte[length];
    }

    /**
     * {@inheritDoc}
     * 
     * {@code PlainBytes} represents the start of a {@link DataContent} chain and
     * therefore must not have any input. Calling this method with a
     * non-{@code null} argument will result in an exception.
     * 
     *
     * @param input the preceding {@link DataContent}, which must be {@code null}
     * @throws IllegalArgumentException if {@code input} is not {@code null}
     */
    @Override
    public void setInput(final DataContent input) {
        if (input != null) {
            throw new IllegalArgumentException(
                    getClass().getName() + " must be the first element in a DataContent chain; it cannot accept input");
        }
    }

    /**
     * Returns an {@link InputStream} for reading the byte array.
     *
     * @return a new {@link ByteArrayInputStream}
     * @throws IOException if an I/O error occurs
     */
    @Override
    public InputStream getStream() throws IOException {
        LOG.log(Level.INFO, "opening byte array for read, length={0}", buffer.length);

        return new ByteArrayInputStream(buffer);
    }

    /**
     * Returns a copy of the internal byte buffer.
     *
     * @return a new byte array containing the data from the internal buffer
     */
    @Override
    public byte[] toBytes() {
        return Arrays.copyOf(buffer, buffer.length);
    }
}
