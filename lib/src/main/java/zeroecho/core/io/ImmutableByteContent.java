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
package zeroecho.core.io;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.OptionalLong;

/**
 * Explicit small-value adapter from immutable bytes to repeatable content.
 *
 * <p>
 * This adapter intentionally materializes its individual value. It is suitable
 * for bounded signatures, public-key fields and external small-object inputs. It
 * must not be used as the authoritative representation of aggregate CRLs, TBS
 * objects or streamed entry sequences.
 * </p>
 */
public final class ImmutableByteContent implements RepeatableContent {

    private final byte[] bytes;
    private final String contentId;

    /**
     * Creates an owned immutable byte value.
     *
     * @param bytes individual value, possibly empty
     * @throws NullPointerException if {@code bytes} is {@code null}
     */
    public ImmutableByteContent(byte[] bytes) {
        byte[] source = Objects.requireNonNull(bytes, "bytes");
        this.bytes = source.clone();
        this.contentId = "sha256:" + digest(this.bytes);
    }

    @Override
    public InputStream openStream() {
        return new ByteArrayInputStream(bytes);
    }

    @Override
    public OptionalLong length() {
        return OptionalLong.of(bytes.length);
    }

    @Override
    public String contentId() {
        return contentId;
    }

    /**
     * Returns a defensive copy for an explicitly bounded provider adapter.
     *
     * @return newly allocated bytes
     */
    public byte[] copyBytes() {
        return bytes.clone();
    }

    @Override
    public void close() {
        // Immutable caller-visible values own no external resources.
    }

    private static String digest(byte[] value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is unavailable", ex);
        }
    }
}
