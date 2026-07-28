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
package zeroecho.core.alg.kyber;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification wrapper for a Kyber (ML-KEM) private key encoded in PKCS#8.
 *
 * <p>
 * Instances of this class carry an owned copy of the PKCS#8-encoded private
 * key bytes. They are used with {@link zeroecho.core.CryptoAlgorithm} key
 * builders to import keys into the provider’s native representation.
 * </p>
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>Format: PKCS#8 DER encoding of a Kyber private key.</li>
 * <li>Stored as a defensive clone.</li>
 * <li>Marshalling/unmarshalling supported via {@link PairSeq} with Base64
 * encoding.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Import a private key into a CryptoAlgorithm
 * byte[] pkcs8Bytes = ...; // obtained from storage
 * KyberPrivateKeySpec spec = new KyberPrivateKeySpec(pkcs8Bytes);
 * PrivateKey k = kyberAlg.privateKeyImporter(KyberPrivateKeySpec.class).importPrivate(spec);
 *
 * // Serialize for persistence
 * PairSeq seq = KyberPrivateKeySpec.marshal(spec);
 *
 * // Deserialize back
 * KyberPrivateKeySpec restored = KyberPrivateKeySpec.unmarshal(seq);
 * }</pre>
 *
 * <p>
 * Access and destruction are synchronized.
 * </p>
 *
 * @see KyberPublicKeySpec
 * @see KyberKeyGenSpec
 */
public final class KyberPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Creates a new spec from PKCS#8-encoded private key bytes.
     *
     * @param pkcs8Der PKCS#8 DER-encoded private key, not null
     * @throws NullPointerException if {@code pkcs8Der} is null
     */
    public KyberPrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der, "pkcs8Der").clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded private key.
     *
     * @return cloned byte array of PKCS#8 DER encoding
     */
    public byte[] pkcs8() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return pkcs8.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Serializes this spec into a {@link PairSeq} using Base64 encoding.
     *
     * <p>
     * The sequence contains:
     * <ul>
     * <li>{@code type} = {@code KyberPrivateKey}</li>
     * <li>{@code pkcs8.b64} = Base64 of PKCS#8 bytes (no padding)</li>
     * </ul>
     *
     * @param spec the spec to marshal
     * @return key-value representation suitable for persistence
     */
    public static PairSeq marshal(KyberPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "KyberPrivateKey", PKCS8_B64, b64);
    }

    /**
     * Reconstructs a {@code KyberPrivateKeySpec} from a {@link PairSeq}.
     *
     * @param p key-value sequence containing a {@code pkcs8.b64} entry
     * @return a new spec with decoded PKCS#8 bytes
     * @throws IllegalArgumentException if the required field is missing
     */
    public static KyberPrivateKeySpec unmarshal(PairSeq p) {
        String pkcs8b64 = null;

        PairSeq.Cursor cur = p.cursor();
        while (cur.next()) {
            String k = cur.key();
            String v = cur.value();
            if (PKCS8_B64.equals(k)) {
                pkcs8b64 = v;
            }
        }
        if (pkcs8b64 == null) {
            throw new IllegalArgumentException("KyberPrivateKeySpec: missing 'pkcs8.b64'");
        }
        byte[] decoded = Base64.getDecoder().decode(pkcs8b64);
        try {
            return new KyberPrivateKeySpec(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Returns a diagnostic string for logging and debugging.
     *
     * <p>
     * Does not expose key material; only length is shown.
     * </p>
     *
     * @return string with length of encoded key
     */
    @Override
    public String toString() {
        return "KyberPrivateKeySpec[len=" + pkcs8.length + "]";
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
            throw new IllegalStateException("Kyber private key specification has been destroyed");
        }
    }
}
