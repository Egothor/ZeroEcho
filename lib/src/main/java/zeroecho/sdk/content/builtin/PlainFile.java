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
package zeroecho.sdk.content.builtin;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.sdk.content.api.DataContent;
import zeroecho.sdk.content.api.PlainContent;

/**
 * A {@link PlainContent} implementation that reads content from a file-like
 * URL.
 */
public final class PlainFile implements PlainContent {
    /**
     * Logger instance for the {@code PlainFile} class used for logging debug,
     * informational, and error messages. Initialized with the class name to provide
     * context-specific logging output.
     */
    private static final Logger LOG = Logger.getLogger(PlainFile.class.getName());

    /**
     * URL representing the location of the file associated with this instance.
     * 
     * This URL may point to a file on the local file system, a remote resource, or
     * any other location accessible via the {@link java.net.URL} protocol. It is
     * final and set during construction.
     */
    private final URL location;

    /**
     * Constructs a PlainFile from the specified URL.
     *
     * @param location the file URL; must not be null
     */
    public PlainFile(final URL location) {
        Objects.requireNonNull(location, "URL must not be null");

        this.location = location;
    }

    /**
     * {@inheritDoc}
     *
     * {@code PlainFile} represents the start of a {@link DataContent} chain and
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
     * Returns an {@link InputStream} for reading from the file.
     *
     * @return an {@link InputStream} from the URL
     * @throws IOException if an I/O error occurs opening the stream
     */
    @Override
    public InputStream getStream() throws IOException {
        LOG.log(Level.INFO, "opening {0}", location);

        return location.openStream();
    }

}
