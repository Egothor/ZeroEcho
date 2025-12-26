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
package zeroecho.sdk.hybrid.kex;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Canonical transcript builder for binding hybrid KEX derivation to public
 * handshake context.
 *
 * <p>
 * The derived hybrid keying material should be bound to protocol context to
 * reduce risk of cross-protocol key reuse and "unknown key-share" style
 * mistakes. This builder provides a deterministic and self-delimiting binary
 * encoding intended to be used as HKDF {@code info}.
 * </p>
 *
 * <h2>Encoding</h2>
 * <p>
 * The transcript is encoded as a sequence of TLV-like entries:
 * </p>
 * <pre>{@code
 * [u16 tagLen][tagBytes...][u32 valueLen][valueBytes...] ...
 * }</pre>
 *
 * <p>
 * Tags are ASCII identifiers (for example {@code "suite"}, {@code "role"},
 * {@code "peerA"}, {@code "peerB"}, {@code "classicMsg"}, {@code "pqcMsg"}).
 * Values are arbitrary bytes. The encoding is stable across JVMs and
 * independent of locale.
 * </p>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Instances are mutable and not thread-safe.
 * </p>
 *
 * @since 1.0
 */
public final class HybridKexTranscript {

    private final ByteArrayOutputStream buffer;
    private final DataOutputStream out;

    /**
     * Creates a new empty transcript.
     */
    public HybridKexTranscript() {
        this.buffer = new ByteArrayOutputStream();
        this.out = new DataOutputStream(buffer);
    }

    /**
     * Adds a UTF-8 string value under a tag.
     *
     * @param tag   ASCII tag identifier
     * @param value UTF-8 string value (must not be null)
     * @return this transcript
     * @throws NullPointerException     if tag or value is null
     * @throws IllegalArgumentException if tag is empty
     */
    public HybridKexTranscript addUtf8(String tag, String value) {
        Objects.requireNonNull(value, "value");
        return addBytes(tag, value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Adds a raw byte value under a tag.
     *
     * <p>
     * The value is defensively copied by the caller if needed; this method does not
     * retain a reference to the provided array.
     * </p>
     *
     * @param tag   ASCII tag identifier
     * @param value byte value (must not be null)
     * @return this transcript
     * @throws NullPointerException     if tag or value is null
     * @throws IllegalArgumentException if tag is empty
     */
    public HybridKexTranscript addBytes(String tag, byte[] value) {
        Objects.requireNonNull(tag, "tag");
        Objects.requireNonNull(value, "value");
        if (tag.isEmpty()) {
            throw new IllegalArgumentException("tag must not be empty");
        }

        byte[] tagBytes = tag.getBytes(StandardCharsets.US_ASCII);

        try {
            if (tagBytes.length > 65_535) { // NOPMD
                throw new IllegalArgumentException("tag too long");
            }
            out.writeShort(tagBytes.length);
            out.write(tagBytes);
            out.writeInt(value.length);
            out.write(value);
            out.flush();
            return this;
        } catch (IOException e) {
            // ByteArrayOutputStream should not throw, but keep failure explicit.
            throw new IllegalStateException("Unable to encode transcript entry", e);
        }
    }

    /**
     * Returns the canonical transcript bytes (defensive copy).
     *
     * @return transcript bytes
     */
    public byte[] toByteArray() {
        return buffer.toByteArray();
    }
}
