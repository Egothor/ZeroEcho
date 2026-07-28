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
package zeroecho.core.alg.dh;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Key specification for a Diffie-Hellman private key encoded in PKCS#8 format.
 *
 * <p>
 * This spec encapsulates the raw encoded private key bytes following the
 * standard PKCS#8 structure. It is used with algorithms in the
 * {@link zeroecho.core.AlgorithmFamily#AGREEMENT} family, allowing safe
 * import/export of DH private keys across contexts.
 * </p>
 *
 * <h2>Design</h2>
 * <ul>
 * <li>Destroyable: the internal byte array is defensively copied at
 * construction and when returned by {@link #encoded()}, and is cleared by
 * {@link #destroy()}.</li>
 * <li>Encodable: supports marshaling to/from a
 * {@link zeroecho.core.marshal.PairSeq} so keys can be serialized in
 * human-readable or protocol-friendly formats.</li>
 * <li>Type-safe: used as a binding for asymmetric key builders within
 * {@code CryptoAlgorithm} definitions.</li>
 * </ul>
 *
 * <h2>Example</h2> <pre>{@code
 * // Import a DH private key from encoded bytes
 * DhPrivateKeySpec spec = new DhPrivateKeySpec(pkcs8Bytes);
 * PrivateKey priv = session.keyBuilders().asymmetric().importPrivate("DH", spec);
 *
 * // Marshal to a text-friendly representation
 * PairSeq ps = DhPrivateKeySpec.marshal(spec);
 *
 * // Unmarshal back to spec
 * DhPrivateKeySpec parsed = DhPrivateKeySpec.unmarshal(ps);
 * }</pre>
 *
 * @since 1.0
 */
public class DhPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Creates a new specification from a PKCS#8 encoded DH private key.
     *
     * @param pkcs8 the encoded private key bytes; must not be {@code null}
     * @throws IllegalArgumentException if {@code pkcs8} is {@code null}
     */
    public DhPrivateKeySpec(byte[] pkcs8) {
        if (pkcs8 == null) {
            throw new IllegalArgumentException("pkcs8 must not be null");
        }
        this.pkcs8 = pkcs8.clone();
    }

    /**
     * Returns a clone of the encoded PKCS#8 bytes.
     *
     * @return a defensive copy of the PKCS#8 encoded DH private key
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
     * Marshals the given DH private key spec into a {@link PairSeq}.
     *
     * <p>
     * The sequence contains a {@code type} field with value {@code "DH-PRIV"} and a
     * {@code pkcs8.b64} field with the Base64 encoding of the key.
     * </p>
     *
     * @param spec the spec to encode
     * @return a {@code PairSeq} representation of the spec
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public static PairSeq marshal(DhPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "DH-PRIV", PKCS8_B64, b64);
    }

    /**
     * Reconstructs a {@code DhPrivateKeySpec} from a {@link PairSeq}.
     *
     * <p>
     * The sequence must contain a {@code pkcs8.b64} field with the Base64-encoded
     * private key. If this field is missing, an {@link IllegalArgumentException} is
     * thrown.
     * </p>
     *
     * @param p the sequence to decode
     * @return a new spec containing the decoded PKCS#8 bytes
     * @throws IllegalArgumentException if required fields are missing or malformed
     */
    public static DhPrivateKeySpec unmarshal(PairSeq p) {
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
            return new DhPrivateKeySpec(out);
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
            throw new IllegalStateException("DH private key specification has been destroyed");
        }
    }
}
