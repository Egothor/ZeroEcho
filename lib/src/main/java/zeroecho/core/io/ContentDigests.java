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

import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/**
 * Streaming integrity helpers for repeatable content.
 */
public final class ContentDigests {

    private static final int BUFFER_BYTES = 16 * 1024;

    private ContentDigests() {
        throw new AssertionError("No instances");
    }

    /**
     * Computes a SHA-256 fingerprint without materializing the aggregate content.
     *
     * @param content      repeatable content
     * @param cancellation runtime cancellation signal
     * @return lowercase hexadecimal SHA-256 fingerprint
     * @throws IOException if the content cannot be read or cancellation is
     *                     requested
     */
    public static String sha256(RepeatableContent content, CancellationSignal cancellation) throws IOException {
        Objects.requireNonNull(content, "content");
        Objects.requireNonNull(cancellation, "cancellation");
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
        byte[] buffer = new byte[BUFFER_BYTES];
        try (InputStream input = content.openStream()) {
            int read;
            while ((read = input.read(buffer)) >= 0) {
                cancellation.throwIfCancelled();
                if (read > 0) {
                    digest.update(buffer, 0, read);
                }
            }
        } finally {
            java.util.Arrays.fill(buffer, (byte) 0);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
}
