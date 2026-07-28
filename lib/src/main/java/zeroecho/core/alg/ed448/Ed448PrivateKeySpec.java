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
package zeroecho.core.alg.ed448;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Ed448 Private Key Specification</h2>
 *
 * Destroyable specification for an Ed448 private key in PKCS#8 encoding.
 *
 * <p>
 * This class acts as a typed carrier for encoded private key material,
 * typically used with {@link Ed448PrivateKeyBuilder} to reconstruct a usable
 * {@link java.security.PrivateKey}. It also provides marshal/unmarshal helpers
 * to serialize the key into a portable {@link PairSeq} representation.
 * </p>
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>The byte array is expected to contain a valid PKCS#8-encoded Ed448
 * private key.</li>
 * <li>Internally, the array is defensively cloned on construction and when
 * returned by {@link #encoded()}.</li>
 * <li>The {@link #marshal(Ed448PrivateKeySpec)} and {@link #unmarshal(PairSeq)}
 * methods wrap and unwrap the PKCS#8 bytes using base64 without padding.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Wrap existing PKCS#8-encoded bytes
 * Ed448PrivateKeySpec spec = new Ed448PrivateKeySpec(pkcs8Bytes);
 *
 * // Import into JCA PrivateKey via builder
 * PrivateKey key = new Ed448PrivateKeyBuilder().importPrivate(spec);
 *
 * // Serialize to PairSeq (e.g., JSON transport)
 * PairSeq p = Ed448PrivateKeySpec.marshal(spec);
 *
 * // Deserialize from PairSeq
 * Ed448PrivateKeySpec restored = Ed448PrivateKeySpec.unmarshal(p);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Access and destruction are synchronized.
 *
 * @since 1.0
 */
public final class Ed448PrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] encodedPkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a new Ed448 private key spec from the given PKCS#8-encoded bytes.
     *
     * @param encodedPkcs8 PKCS#8-encoded Ed448 private key (non-null)
     * @throws IllegalArgumentException if {@code encodedPkcs8} is {@code null}
     */
    public Ed448PrivateKeySpec(byte[] encodedPkcs8) {
        if (encodedPkcs8 == null) {
            throw new IllegalArgumentException("encodedPkcs8 must not be null");
        }
        this.encodedPkcs8 = encodedPkcs8.clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded private key bytes.
     *
     * @return cloned PKCS#8-encoded key bytes
     */
    public byte[] encoded() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return encodedPkcs8.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Serializes this key spec into a {@link PairSeq} record.
     *
     * <p>
     * The encoding is base64 without padding. The {@code type} field is set to
     * {@code "Ed448-PRIV"}, and the PKCS#8 bytes are stored under the key
     * {@code "pkcs8.b64"}.
     * </p>
     *
     * @param spec the key spec to serialize
     * @return a {@link PairSeq} containing the type and base64 data
     */
    public static PairSeq marshal(Ed448PrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "Ed448-PRIV", PKCS8_B64, b64);
    }

    /**
     * Deserializes a {@link PairSeq} into a new {@link Ed448PrivateKeySpec}.
     *
     * <p>
     * Expects a field {@code "pkcs8.b64"} containing the base64-encoded PKCS#8
     * private key bytes. Other fields are ignored.
     * </p>
     *
     * @param p the serialized pair sequence
     * @return a reconstructed {@link Ed448PrivateKeySpec}
     * @throws IllegalArgumentException if {@code pkcs8.b64} is missing
     */
    public static Ed448PrivateKeySpec unmarshal(PairSeq p) {
        byte[] out = null;
        PairSeq.Cursor cur = p.cursor();
        while (cur.next()) {
            String k = cur.key();
            String v = cur.value();
            if (PKCS8_B64.equals(k)) {
                out = decodeReplacing(out, v);
            }
        }
        if (out == null) {
            throw new IllegalArgumentException("pkcs8.b64 missing for Ed448 private key");
        }
        try {
            return new Ed448PrivateKeySpec(out);
        } finally {
            Arrays.fill(out, (byte) 0);
        }
    }

    private static byte[] decodeReplacing(byte[] current, String encoded) {
        if (current != null) {
            Arrays.fill(current, (byte) 0);
        }
        return Base64.getDecoder().decode(encoded);
    }

    private String encodedKey() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return Base64.getEncoder().withoutPadding().encodeToString(encodedPkcs8);
        } finally {
            lifecycleLock.unlock();
        }
    }

    @Override
    public void destroy() {
        lifecycleLock.lock();
        try {
            if (!destroyed) {
                Arrays.fill(encodedPkcs8, (byte) 0);
                destroyed = true;
            }
        } finally {
            lifecycleLock.unlock();
        }
    }

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
            throw new IllegalStateException("Ed448 private key specification has been destroyed");
        }
    }
}
