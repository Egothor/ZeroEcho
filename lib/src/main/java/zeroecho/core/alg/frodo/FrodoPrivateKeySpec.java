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
package zeroecho.core.alg.frodo;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for importing a Frodo private key</h2>
 *
 * {@code FrodoPrivateKeySpec} is a simple wrapper around a PKCS#8-encoded
 * FrodoKEM private key. It provides defensive access to the raw encoding and
 * utilities for serialization.
 *
 * <h2>Encoding format</h2>
 * <ul>
 * <li>Keys are stored in the standard PKCS#8 DER format as produced by
 * providers such as BouncyCastle PQC.</li>
 * <li>The encoding is preserved exactly as given; no internal parsing or
 * validation occurs in this class.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <ul>
 * <li>Instances of this spec can be passed to
 * {@link zeroecho.sdk.KeyBuilders.Asymmetric#importPrivate(String, AlgorithmKeySpec)}
 * to construct a usable {@link java.security.PrivateKey} object.</li>
 * <li>The {@link #marshal(FrodoPrivateKeySpec)} and {@link #unmarshal(PairSeq)}
 * helpers allow safe conversion to/from structured textual form for persistence
 * or transmission.</li>
 * </ul>
 *
 * <pre>{@code
 * // Import an existing Frodo private key
 * byte[] encoded = Files.readAllBytes(Paths.get("frodo.key"));
 * FrodoPrivateKeySpec spec = new FrodoPrivateKeySpec(encoded);
 * PrivateKey priv = session.keyBuilders().asymmetric().importPrivate("FrodoKEM", spec);
 * }</pre>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * The internal byte array is cloned on construction and when accessed via
 * {@link #pkcs8()}. Access and destruction are synchronized.
 * </p>
 *
 * @since 1.0
 */
public final class FrodoPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Creates a new specification from a PKCS#8 DER-encoded key.
     *
     * @param pkcs8Der the encoded private key bytes (will be cloned)
     * @throws NullPointerException if {@code pkcs8Der} is {@code null}
     */
    public FrodoPrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der).clone();
    }

    /**
     * Returns a clone of the underlying PKCS#8 encoding.
     *
     * @return defensive copy of the PKCS#8-encoded private key
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
     * Serializes this spec into a {@link PairSeq}, encoding the key as Base64
     * without padding.
     *
     * @param spec Frodo private key specification to serialize
     * @return a {@code PairSeq} with type and Base64-encoded key
     */
    public static PairSeq marshal(FrodoPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "FrodoPrivateKeySpec", PKCS8_B64, b64);
    }

    /**
     * Parses a {@link PairSeq} previously produced by
     * {@link #marshal(FrodoPrivateKeySpec)}.
     *
     * @param p input sequence containing a {@code pkcs8.b64} entry
     * @return a new private key spec initialized with the decoded bytes
     * @throws IllegalArgumentException if {@code pkcs8.b64} entry is missing
     */
    public static FrodoPrivateKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (PKCS8_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("FrodoPrivateKeySpec: missing pkcs8.b64");
        }
        byte[] decoded = Base64.getDecoder().decode(b64);
        try {
            return new FrodoPrivateKeySpec(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Returns a diagnostic string containing the encoded length.
     *
     * @return string in the form {@code FrodoPrivateKeySpec[len=N]}
     */
    @Override
    public String toString() {
        return "FrodoPrivateKeySpec[len=" + pkcs8.length + "]";
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
            throw new IllegalStateException("Frodo private key specification has been destroyed");
        }
    }
}
