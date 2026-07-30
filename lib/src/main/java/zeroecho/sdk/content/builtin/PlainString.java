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
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * A {@link PlainContent} implementation that wraps a UTF-8 string.
 * 
 * @author Leo Galambos
 */
public class PlainString implements PlainContent {
    /**
     * Logger instance for the {@code PlainString} class used to log informational,
     * debug, or error messages related to the class’s operations.
     * 
     * The logger is initialized with the name of the {@code PlainString} class,
     * enabling targeted and organized logging output.
     */
    private static final Logger LOG = Logger.getLogger(PlainString.class.getName());

    /**
     * The plain text content represented by this instance.
     */
    protected String str;

    /**
     * Constructs a PlainString with the given string.
     *
     * @param str the plain text content; must not be null
     */
    public PlainString(final String str) {
        Objects.requireNonNull(str, "plain string must not be null");

        this.str = str;
    }

    /**
     * Returns the original string content.
     *
     * @return the string
     */
    @Override
    public String toText() {
        return str;
    }

    /**
     * {@inheritDoc}
     * 
     * {@code PlainString} represents the start of a {@link DataContent} chain and
     * therefore must not have any input. Calling this method with a
     * non-{@code null} argument will result in an exception.
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
     * Returns an {@link InputStream} of the UTF-8 encoded string.
     *
     * @return a {@link ByteArrayInputStream}
     */
    @Override
    public InputStream getStream() {
        LOG.log(Level.FINE, "opening \"{0}\"", str);
        return new ByteArrayInputStream(toBytes());
    }

    /**
     * Returns the UTF-8 encoded byte array of the string.
     *
     * @return a byte array representation
     */
    @Override
    public byte[] toBytes() {
        return str.getBytes(StandardCharsets.UTF_8);
    }
}
