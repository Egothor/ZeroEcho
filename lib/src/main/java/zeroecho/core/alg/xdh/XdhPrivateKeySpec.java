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
package zeroecho.core.alg.xdh;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Key specification for an XDH (elliptic curve Diffie-Hellman) private key.
 *
 * <p>
 * This class encapsulates the PKCS#8-encoded representation of a private key
 * used in modern Diffie-Hellman style agreements such as X25519 or X448. It
 * provides safe construction, serialization, and deserialization utilities
 * suitable for persistence, transmission, or integration with
 * {@link zeroecho.core.CryptoAlgorithm} key builders.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li>Encapsulation: the encoded key bytes are cloned defensively on input and
 * output to prevent accidental modification.</li>
 * <li>Interoperability: supports round-trip conversion to/from
 * {@link zeroecho.core.marshal.PairSeq} with base64 encoding.</li>
 * <li>Validation: throws explicit exceptions when mandatory fields are
 * missing.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Construct from a PKCS#8-encoded private key
 * byte[] encoded = ...; // obtained from key generation or storage
 * XdhPrivateKeySpec spec = new XdhPrivateKeySpec(encoded);
 *
 * // Marshal to a serializable structure
 * PairSeq p = XdhPrivateKeySpec.marshal(spec);
 *
 * // Unmarshal back from serialized form
 * XdhPrivateKeySpec spec2 = XdhPrivateKeySpec.unmarshal(p);
 *
 * assert Arrays.equals(spec.encoded(), spec2.encoded());
 * }</pre>
 *
 * @since 1.0
 */
public class XdhPrivateKeySpec implements AlgorithmKeySpec, Destroyable {
    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a new specification from the given PKCS#8-encoded private key.
     *
     * @param pkcs8 the raw encoded key bytes, must not be {@code null}
     * @throws IllegalArgumentException if {@code pkcs8} is {@code null}
     */
    public XdhPrivateKeySpec(byte[] pkcs8) {
        if (pkcs8 == null) {
            throw new IllegalArgumentException("pkcs8 must not be null");
        }
        this.pkcs8 = pkcs8.clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded private key bytes.
     *
     * @return a clone of the internal key encoding
     */
    public byte[] encoded() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return pkcs8.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Serializes the given key specification into a {@link PairSeq} with base64
     * encoding.
     *
     * <p>
     * The output contains two entries:
     * <ul>
     * <li>{@code type = "XDH-PRIV"}</li>
     * <li>{@code pkcs8.b64 = <base64-encoded key>}</li>
     * </ul>
     *
     * @param spec the specification to marshal
     * @return a pair sequence containing the encoded key
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public static PairSeq marshal(XdhPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "XDH-PRIV", PKCS8_B64, b64);
    }

    /**
     * Deserializes a specification from the given {@link PairSeq}.
     *
     * <p>
     * The sequence must contain an entry {@code pkcs8.b64} with a base64-encoded
     * key. Additional entries are ignored.
     * </p>
     *
     * @param p the pair sequence containing serialized fields
     * @return a reconstructed {@code XdhPrivateKeySpec}
     * @throws IllegalArgumentException if {@code pkcs8.b64} is missing or cannot be
     *                                  decoded
     */
    public static XdhPrivateKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("pkcs8.b64 missing for DH private key");
        }
        try {
            return new XdhPrivateKeySpec(out);
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
            return Base64.getEncoder().withoutPadding().encodeToString(pkcs8);
        } finally {
            lifecycleLock.unlock();
        }
    }

    @Override
    public void destroy() {
        lifecycleLock.lock();
        try {
            if (!destroyed) {
                Arrays.fill(pkcs8, (byte) 0);
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
            throw new IllegalStateException("XDH private key specification has been destroyed");
        }
    }
}
