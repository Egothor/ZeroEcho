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
package zeroecho.ext.integrations.stegano;

import java.io.IOException;
import java.io.InputStream;

/**
 * Contract for stream-based steganographic methods.
 *
 * <p>
 * Implementations of this interface provide algorithms to hide and recover
 * messages in digital images. Streams are used for both image data and message
 * payloads to support large files and efficient, pipeline-friendly processing.
 * </p>
 *
 * <p>
 * A typical implementation will consume an input image stream, apply an
 * embedding or extraction algorithm, and return a new stream without requiring
 * the entire image to reside in memory.
 * </p>
 */
public interface SteganographyMethod {

    /**
     * Embeds a message into a source image and produces a new image in the
     * requested format.
     *
     * <p>
     * The caller provides an input image, a message stream, and specifies the
     * desired output format. The implementation applies its embedding algorithm and
     * returns an {@link InputStream} representing the new image.
     * </p>
     *
     * @param inputImage   the source image stream; format may vary depending on
     *                     implementation capabilities
     * @param outputFormat the desired format for the resulting image; must be
     *                     supported and generally lossless (for example,
     *                     {@link ImageFormat#PNG})
     * @param message      the stream containing the message to be embedded in the
     *                     image
     * @return an input stream of the new image containing the embedded message,
     *         encoded in the requested format
     * @throws IOException              if an I/O error occurs while reading or
     *                                  writing streams
     * @throws IllegalArgumentException if the specified output format is not
     *                                  supported by this method
     */
    InputStream embed(InputStream inputImage, ImageFormat outputFormat, InputStream message) throws IOException;

    /**
     * Extracts a hidden message from an image.
     *
     * <p>
     * The caller supplies an image stream that contains an embedded message. The
     * implementation applies its extraction algorithm and returns the recovered
     * message as a new stream.
     * </p>
     *
     * @param inputImage the image stream containing an embedded message; must be in
     *                   a format compatible with this method
     * @return an input stream of the extracted message data
     * @throws IOException if an I/O error occurs while reading or writing streams
     */
    InputStream extract(InputStream inputImage) throws IOException;

    /**
     * Returns metadata describing this steganographic method.
     *
     * <p>
     * The metadata includes a short identifier, a descriptive name, and a textual
     * explanation of the embedding technique.
     * </p>
     *
     * @return the metadata object associated with this steganographic method
     */
    StegoMetadata getMetadata();
}
