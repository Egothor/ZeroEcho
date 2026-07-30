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
package zeroecho.core.alg.hmac;

import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.annotation.Describable;
import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification for importing raw HMAC keys into a
 * {@link javax.crypto.SecretKey}.
 *
 * <p>
 * {@code HmacKeyImportSpec} describes how existing key material for an HMAC
 * algorithm (for example, {@code "HmacSHA256"}) should be wrapped into a
 * {@link javax.crypto.SecretKey}. Unlike {@link HmacKeyGenSpec}, which requests
 * generation of fresh random keys, this class is used when the caller already
 * possesses key material in raw, hexadecimal, or Base64-encoded form.
 * </p>
 *
 * <h2>Fields</h2>
 * <ul>
 * <li>{@code macName}: canonical HMAC algorithm name (for example,
 * {@code "HmacSHA256"}).</li>
 * <li>{@code key}: the raw key material as a byte array (defensively
 * copied).</li>
 * </ul>
 *
 * <h2>Typical usage</h2>
 * <h3>Import from raw bytes</h3> <pre>
 * {@code
 * byte[] rawKey = Files.readAllBytes(Paths.get("hmac.key"));
 * HmacKeyImportSpec spec = HmacKeyImportSpec.fromRaw("HmacSHA256", rawKey);
 * SecretKey key = session.keyBuilders().symmetric().importKey("HMAC", spec);
 * }
 * </pre>
 *
 * <h3>Import from hex/Base64</h3> <pre>
 * {@code
 * HmacKeyImportSpec specHex =
 *     HmacKeyImportSpec.fromHex("HmacSHA256", "aabbccddeeff00112233");
 *
 * HmacKeyImportSpec specB64 =
 *     HmacKeyImportSpec.fromBase64("HmacSHA256", "Khsz95oU+7H0Ow==");
 * }
 * </pre>
 *
 * <h2>Serialization</h2>
 * <ul>
 * <li>{@link #marshal(HmacKeyImportSpec)} encodes a spec into a {@link PairSeq}
 * with fields {@code type=HMAC-KEY}, {@code mac}, and {@code k.b64} (Base64
 * without padding).</li>
 * <li>{@link #unmarshal(PairSeq)} decodes a spec, accepting {@code k.b64} or
 * {@code k.hex}.</li>
 * </ul>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>Imported keys are cloned defensively; callers should erase the original
 * buffers if sensitive.</li>
 * <li>Validate the key length for the chosen digest family (for example, 256
 * bits for HmacSHA256).</li>
 * <li>Do not reuse the same key across different algorithms.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class HmacKeyImportSpec implements AlgorithmKeySpec, Describable, Destroyable {
    private final String macName;
    private final byte[] key;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a new HMAC key import specification.
     *
     * @param macName algorithm name (e.g., {@code "HmacSHA256"})
     * @param key     raw key material; must not be {@code null}
     * @throws NullPointerException if {@code macName} or {@code key} is
     *                              {@code null}
     */
    public HmacKeyImportSpec(String macName, byte[] key) {
        this.macName = Objects.requireNonNull(macName, "macName must not be null");
        this.key = Objects.requireNonNull(key, "key must not be null").clone();
    }

    /**
     * Returns the HMAC algorithm name.
     *
     * @return algorithm name string (e.g., {@code "HmacSHA256"})
     */
    public String macName() {
        return macName;
    }

    /**
     * Returns a defensive copy of the raw key material.
     *
     * @return cloned key bytes
     */
    public byte[] key() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return key.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Creates a spec from raw bytes.
     *
     * @param macName algorithm name (e.g., {@code "HmacSHA256"})
     * @param key     raw key material
     * @return a new {@code HmacKeyImportSpec}
     */
    public static HmacKeyImportSpec fromRaw(String macName, byte[] key) {
        return new HmacKeyImportSpec(macName, key);
    }

    /**
     * Creates a spec from a hex-encoded key string.
     *
     * @param macName algorithm name (e.g., {@code "HmacSHA256"})
     * @param hex     key material encoded as hexadecimal
     * @return a new {@code HmacKeyImportSpec}
     * @throws NullPointerException if {@code hex} is {@code null}
     */
    public static HmacKeyImportSpec fromHex(String macName, String hex) {
        Objects.requireNonNull(hex, "hex must not be null");
        byte[] decoded = HexFormat.of().parseHex(hex);
        try {
            return fromRaw(macName, decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Creates a spec from a Base64-encoded key string.
     *
     * @param macName algorithm name (e.g., {@code "HmacSHA256"})
     * @param b64     key material encoded in Base64
     * @return a new {@code HmacKeyImportSpec}
     * @throws NullPointerException if {@code b64} is {@code null}
     */
    public static HmacKeyImportSpec fromBase64(String macName, String b64) {
        Objects.requireNonNull(b64, "base64 must not be null");
        byte[] decoded = Base64.getDecoder().decode(b64);
        try {
            return fromRaw(macName, decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Returns a short human-readable description of this spec.
     *
     * <p>
     * The description is the algorithm name (e.g., {@code "HmacSHA256"}).
     * </p>
     *
     * @return algorithm name
     */
    @Override
    public String description() {
        return macName;
    }

    /**
     * Serializes a spec into a {@link PairSeq}.
     *
     * @param spec the spec to serialize
     * @return encoded key spec sequence
     */
    public static PairSeq marshal(HmacKeyImportSpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "HMAC-KEY", "mac", spec.macName, "k.b64", b64);
    }

    /**
     * Deserializes a spec from a {@link PairSeq}.
     *
     * <p>
     * Accepts key material encoded as {@code k.b64} (Base64) or {@code k.hex}
     * (hexadecimal).
     * </p>
     *
     * @param p sequence containing encoded spec fields
     * @return a reconstructed {@code HmacKeyImportSpec}
     * @throws IllegalArgumentException if {@code mac} or key material is missing
     */
    public static HmacKeyImportSpec unmarshal(PairSeq p) {
        String mac = null;
        byte[] key = null;

        try {
            PairSeq.Cursor cur = p.cursor();
            while (cur.next()) {
                String k = cur.key();
                String v = cur.value();
                switch (k) {
                    case "mac" -> mac = v;
                    case "k.b64" -> {
                        wipe(key);
                        key = Base64.getDecoder().decode(v);
                    }
                    case "k.hex" -> {
                        wipe(key);
                        key = HexFormat.of().parseHex(v);
                    }
                    default -> {
                    }
                }
            }
            if (mac == null) {
                throw new IllegalArgumentException("mac missing for HMAC key");
            }
            if (key == null) {
                throw new IllegalArgumentException("HMAC key missing (k.b64 or k.hex)");
            }
            return new HmacKeyImportSpec(mac, key);
        } finally {
            wipe(key);
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
            throw new IllegalStateException("HMAC key import specification has been destroyed");
        }
    }
}
