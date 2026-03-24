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
package zeroecho.core.alg.chacha;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>ChaCha20 key import specification</h2>
 *
 * Wraps a raw ChaCha20 key for import into the ZeroEcho framework. Keys must be
 * exactly 32 bytes (256 bits).
 *
 * <h3>Construction</h3>
 * <ul>
 * <li>{@link #fromRaw(byte[])} - construct from a raw byte array.</li>
 * <li>{@link #fromHex(String)} - construct from a hexadecimal string.</li>
 * <li>{@link #fromBase64(String)} - construct from a Base64 string.</li>
 * </ul>
 *
 * <h3>Marshalling</h3> Keys can be serialized/deserialized using
 * {@link PairSeq}:
 * <ul>
 * <li>{@link #marshal(ChaChaKeyImportSpec)} encodes the key as Base64.</li>
 * <li>{@link #unmarshal(PairSeq)} accepts fields {@code k.b64}, {@code k.hex},
 * or {@code k.raw} (ISO-8859-1) to restore a spec.</li>
 * </ul>
 *
 * <h3>Usage</h3> <pre>{@code
 * // Import from raw key bytes
 * ChaChaKeyImportSpec spec = ChaChaKeyImportSpec.fromRaw(keyBytes);
 * SecretKey key = cryptoAlgorithm.importSecret(spec);
 *
 * // Serialize to PairSeq
 * PairSeq seq = ChaChaKeyImportSpec.marshal(spec);
 *
 * // Deserialize back
 * ChaChaKeyImportSpec restored = ChaChaKeyImportSpec.unmarshal(seq);
 * }</pre>
 *
 * @since 1.0
 */
public final class ChaChaKeyImportSpec implements AlgorithmKeySpec {
    private final byte[] key;

    /**
     * Creates a new import spec with the given raw key.
     *
     * @param key raw 32-byte key
     * @throws NullPointerException     if {@code key} is null
     * @throws IllegalArgumentException if {@code key.length != 32}
     */
    private ChaChaKeyImportSpec(byte[] key) {
        Objects.requireNonNull(key, "key must not be null");
        if (key.length != 32) { // NOPMD
            throw new IllegalArgumentException("ChaCha20 key must be 32 bytes, got " + key.length);
        }
        this.key = Arrays.copyOf(key, 32);
    }

    /**
     * Creates a spec from a raw byte array.
     *
     * @param key 32-byte raw key
     * @return spec wrapping the key
     */
    public static ChaChaKeyImportSpec fromRaw(byte[] key) {
        return new ChaChaKeyImportSpec(key);
    }

    /**
     * Creates a spec from a hexadecimal string.
     *
     * @param hex hex-encoded key
     * @return spec wrapping the decoded key
     */
    public static ChaChaKeyImportSpec fromHex(String hex) {
        return fromRaw(HexFormat.of().parseHex(hex));
    }

    /**
     * Creates a spec from a Base64 string.
     *
     * @param b64 base64-encoded key
     * @return spec wrapping the decoded key
     */
    public static ChaChaKeyImportSpec fromBase64(String b64) {
        return fromRaw(Base64.getDecoder().decode(b64));
    }

    /**
     * Returns a defensive copy of the raw key.
     *
     * @return 32-byte key array
     */
    public byte[] key() {
        return Arrays.copyOf(key, key.length);
    }

    /**
     * Serializes this spec into a {@link PairSeq}, storing the key as Base64.
     *
     * @param spec spec to serialize
     * @return serialized key representation
     */
    public static PairSeq marshal(ChaChaKeyImportSpec spec) {
        String k = Base64.getEncoder().withoutPadding().encodeToString(spec.key);
        return PairSeq.of("type", "CHACHA-KEY", "k.b64", k);
    }

    /**
     * Restores a spec from a serialized {@link PairSeq}.
     *
     * <p>
     * Recognized fields:
     * </p>
     * <ul>
     * <li>{@code k.b64} - Base64 encoding</li>
     * <li>{@code k.hex} - hexadecimal string</li>
     * <li>{@code k.raw} - raw ISO-8859-1 string</li>
     * </ul>
     *
     * @param p serialized key representation
     * @return reconstructed spec
     * @throws IllegalArgumentException if none of the recognized fields are present
     */
    public static ChaChaKeyImportSpec unmarshal(PairSeq p) {
        byte[] out = null;
        PairSeq.Cursor c = p.cursor();
        while (c.next()) {
            String k = c.key();
            String v = c.value();
            switch (k) {
                case "k.b64" -> out = Base64.getDecoder().decode(v);
                case "k.hex" -> out = HexFormat.of().parseHex(v);
                case "k.raw" -> out = v.getBytes(StandardCharsets.ISO_8859_1);
                default -> {
                }
            }
        }
        if (out == null) {
            throw new IllegalArgumentException("ChaCha20 key missing (k.b64 / k.hex / k.raw)");
        }
        return new ChaChaKeyImportSpec(out);
    }
}
