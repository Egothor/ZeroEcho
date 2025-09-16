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
package zeroecho.sdk.integrations.stegano;

/**
 * Enumeration of image formats supported for steganographic processing.
 *
 * <p>
 * These formats are chosen because they provide predictable binary layouts and
 * are commonly used in practical steganographic embedding and extraction.
 * </p>
 */
public enum ImageFormat {
    /**
     * Portable Network Graphics format.
     * <p>
     * PNG uses lossless compression, which makes it suitable for precise bit-level
     * embedding without introducing distortion into the carrier image.
     * </p>
     */
    PNG,
    /**
     * Bitmap format.
     * <p>
     * BMP is an uncompressed raster format. Its simple and direct structure makes
     * it reliable for low-level manipulation during steganographic processing.
     * </p>
     */
    BMP,
    /**
     * Joint Photographic Experts Group format.
     * <p>
     * JPEG is a lossy format based on DCT (Discrete Cosine Transform) blocks.
     * Steganographic methods for JPEG must work safely within the compression
     * domain to preserve image integrity while embedding data.
     * </p>
     */
    JPEG
}
