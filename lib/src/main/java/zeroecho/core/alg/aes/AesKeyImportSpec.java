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
package zeroecho.core.alg.aes;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification for importing an existing AES key.
 *
 * <p>
 * This class wraps raw key material (16, 24, or 32 bytes) for use with the AES
 * algorithm. Factory methods support construction from raw bytes, hex strings,
 * or Base64-encoded strings. The key material is defensively copied.
 * </p>
 *
 * <p>
 * Instances are consumed by the AES key builder to produce a
 * {@link javax.crypto.SecretKey}.
 * </p>
 *
 * <p>
 * Objects of this type are thread-safe while active and may be destroyed to
 * wipe their owned key bytes. Access and marshalling fail after destruction.
 * </p>
 *
 * @since 1.0
 */
public final class AesKeyImportSpec implements AlgorithmKeySpec, Destroyable {
    private final byte[] key;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    private AesKeyImportSpec(byte[] key) {
        Objects.requireNonNull(key, "key must not be null");
        int len = key.length;
        if (len != 16 && len != 24 && len != 32) {
            throw new IllegalArgumentException("AES key must be 16/24/32 bytes, got " + len);
        }
        this.key = Arrays.copyOf(key, len);
    }

    /**
     * Creates a specification from raw key bytes.
     *
     * @param key a 16, 24, or 32 byte array
     * @return an import specification
     * @throws IllegalArgumentException if the length is invalid
     */
    public static AesKeyImportSpec fromRaw(byte[] key) {
        return new AesKeyImportSpec(key);
    }

    /**
     * Creates a specification from a hex-encoded string.
     *
     * @param hex a string of 32, 48, or 64 hex characters
     * @return an import specification
     * @throws NullPointerException     if {@code hex} is null
     * @throws IllegalArgumentException if decoded length is invalid
     */
    public static AesKeyImportSpec fromHex(String hex) {
        Objects.requireNonNull(hex, "hex must not be null");
        byte[] decoded = HexFormat.of().parseHex(hex);
        try {
            return fromRaw(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Creates a specification from a Base64-encoded string.
     *
     * @param b64 Base64 text without padding
     * @return an import specification
     * @throws NullPointerException     if {@code b64} is null
     * @throws IllegalArgumentException if decoded length is invalid
     */
    public static AesKeyImportSpec fromBase64(String b64) {
        Objects.requireNonNull(b64, "base64 must not be null");
        byte[] decoded = Base64.getDecoder().decode(b64);
        try {
            return fromRaw(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Returns a defensive copy of the key bytes.
     *
     * @return the raw key material
     */
    public byte[] key() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return Arrays.copyOf(key, key.length);
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Serializes this specification into a key/value sequence, encoding the key in
     * Base64.
     *
     * @param spec the specification to marshal
     * @return a sequence containing the key data
     */
    public static PairSeq marshal(AesKeyImportSpec spec) {
        String k = spec.encodedKey();
        return PairSeq.of("type", "AES-KEY", "k.b64", k);
    }

    /**
     * Reconstructs a specification from a key/value sequence. Accepts keys under
     * {@code k.b64}, {@code k.hex}, or {@code k.raw}.
     *
     * @param p the sequence to parse
     * @return a reconstructed import specification
     * @throws IllegalArgumentException if no key is present
     */
    public static AesKeyImportSpec unmarshal(PairSeq p) {
        byte[] out = null;
        try {
            PairSeq.Cursor cur = p.cursor();
            while (cur.next()) {
                String k = cur.key();
                String v = cur.value();
                switch (k) {
                    case "k.b64" -> {
                        wipe(out);
                        out = Base64.getDecoder().decode(v);
                    }
                    case "k.hex" -> {
                        wipe(out);
                        out = HexFormat.of().parseHex(v);
                    }
                    case "k.raw" -> {
                        wipe(out);
                        out = v.getBytes(StandardCharsets.ISO_8859_1);
                    }
                    default -> {
                        /* ignore */ }
                }
            }
            if (out == null) {
                throw new IllegalArgumentException("AES key missing (k.b64 / k.hex / k.raw)");
            }
            return new AesKeyImportSpec(out);
        } finally {
            wipe(out);
        }
    }

    private static void wipe(byte[] current) {
        if (current != null) {
            Arrays.fill(current, (byte) 0);
        }
    }

    private String encodedKey() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return Base64.getEncoder().withoutPadding().encodeToString(key);
        } finally {
            lifecycleLock.unlock();
        }
    }

    /** {@inheritDoc} */
    @Override
    public void destroy() {
        lifecycleLock.lock();
        try {
            if (!destroyed) {
                Arrays.fill(key, (byte) 0);
                destroyed = true;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

    /** {@inheritDoc} */
    @Override
    public boolean isDestroyed() {
        lifecycleLock.lock();
        try {
            return destroyed;
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void ensureActive() {
        if (destroyed) {
            throw new IllegalStateException("AES key import specification has been destroyed");
        }
    }
}
