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
package zeroecho.core.alg.ed25519;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for Ed25519 private keys</h2>
 *
 * {@link zeroecho.core.spec.AlgorithmKeySpec} representing an Ed25519 private
 * key in its encoded PKCS#8 form.
 *
 * <p>
 * This spec is used by {@link Ed25519PrivateKeyBuilder} and related APIs to
 * import and wrap Ed25519 private keys. The encoding is expected to conform to
 * the PKCS#8 standard as produced by standard JCA key factories or external
 * tooling.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Encapsulates the PKCS#8-encoded private key bytes.</li>
 * <li>Provides safe cloning to avoid exposing mutable internal state.</li>
 * <li>Supports serialization to and from a compact base64-based {@link PairSeq}
 * representation via {@link #marshal(Ed25519PrivateKeySpec)} and
 * {@link #unmarshal(PairSeq)}.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Wrap PKCS#8 bytes in a spec
 * Ed25519PrivateKeySpec spec = new Ed25519PrivateKeySpec(pkcs8Bytes);
 *
 * // Import into a PrivateKey using ZeroEcho
 * PrivateKey priv = session.keyBuilders().asymmetric().importPrivate("Ed25519", spec);
 *
 * // Serialize to PairSeq (e.g., for configuration or transport)
 * PairSeq seq = Ed25519PrivateKeySpec.marshal(spec);
 *
 * // Reconstruct from serialized form
 * Ed25519PrivateKeySpec restored = Ed25519PrivateKeySpec.unmarshal(seq);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Access and destruction are synchronized. The internal
 * key bytes are defensively copied on construction and retrieval.
 *
 * @since 1.0
 */
public final class Ed25519PrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] encodedPkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Creates a new Ed25519 private key specification from its PKCS#8 encoding.
     *
     * @param encodedPkcs8 PKCS#8-encoded private key bytes; must not be null
     * @throws IllegalArgumentException if {@code encodedPkcs8} is null
     */
    public Ed25519PrivateKeySpec(byte[] encodedPkcs8) {
        if (encodedPkcs8 == null) {
            throw new IllegalArgumentException("encodedPkcs8 must not be null");
        }
        this.encodedPkcs8 = encodedPkcs8.clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded private key bytes.
     *
     * @return clone of the PKCS#8 encoding
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
     * Serializes the given private key spec to a base64-encoded {@link PairSeq}.
     *
     * <p>
     * The output includes a type marker ({@code "Ed25519-PRIV"}) and the field
     * {@code "pkcs8.b64"} containing the base64 representation of the key.
     * </p>
     *
     * @param spec private key spec to marshal
     * @return serialized representation as a {@link PairSeq}
     */
    public static PairSeq marshal(Ed25519PrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "Ed25519-PRIV", PKCS8_B64, b64);
    }

    /**
     * Reconstructs a private key spec from a base64-encoded {@link PairSeq}.
     *
     * <p>
     * The sequence must contain the field {@code "pkcs8.b64"} with the base64
     * encoding of the PKCS#8 key.
     * </p>
     *
     * @param p serialized key data
     * @return a new {@code Ed25519PrivateKeySpec} instance
     * @throws IllegalArgumentException if the sequence does not contain
     *                                  {@code "pkcs8.b64"}
     */
    public static Ed25519PrivateKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("pkcs8.b64 missing for Ed25519 private key");
        }
        try {
            return new Ed25519PrivateKeySpec(out);
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
            throw new IllegalStateException("Ed25519 private key specification has been destroyed");
        }
    }
}
