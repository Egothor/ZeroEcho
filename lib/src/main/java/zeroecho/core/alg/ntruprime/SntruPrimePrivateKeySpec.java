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
package zeroecho.core.alg.ntruprime;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Specification wrapper for an encoded SNTRU Prime private key in PKCS#8
 * format.
 *
 * <p>
 * {@code SntruPrimePrivateKeySpec} provides a type-safe holder for
 * PKCS#8-encoded private key material belonging to the SNTRU Prime KEM. It is
 * destroyable, and defensive copies are made on construction and retrieval.
 * </p>
 *
 * <h2>Usage</h2> Instances are typically created after parsing or receiving
 * encoded key data, and passed to an algorithm’s key builder to import a usable
 * {@link java.security.PrivateKey}.
 *
 * <pre>{@code
 * // Wrap existing encoded key
 * byte[] pkcs8 = Files.readAllBytes(Paths.get("sntru-private.pk8"));
 * SntruPrimePrivateKeySpec spec = new SntruPrimePrivateKeySpec(pkcs8);
 *
 * // Import via CryptoAlgorithms
 * PrivateKey priv = session.keyBuilders().asymmetric().importPrivate("SNTRUPrime", spec);
 * }</pre>
 *
 * <h2>Serialization</h2> A lightweight marshaling format is supported via
 * {@link PairSeq}:
 * <ul>
 * <li>{@link #marshal(SntruPrimePrivateKeySpec)} produces a base64 string under
 * the key {@code "pkcs8.b64"}.</li>
 * <li>{@link #unmarshal(PairSeq)} reconstructs a new spec instance from such a
 * sequence.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class SntruPrimePrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a new private key specification from a PKCS#8-encoded byte array.
     *
     * <p>
     * A defensive copy is made; the input array may be reused or modified without
     * affecting this instance.
     * </p>
     *
     * @param pkcs8Der PKCS#8 encoded private key bytes (DER form)
     * @throws NullPointerException if {@code pkcs8Der} is null
     */
    public SntruPrimePrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der).clone();
    }

    /**
     * Returns a clone of the PKCS#8-encoded private key bytes.
     *
     * @return copy of the encoded private key
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
     * Serializes this specification into a {@link PairSeq}.
     *
     * <p>
     * The result contains:
     * <ul>
     * <li>{@code type = "SntruPrimePrivateKeySpec"}</li>
     * <li>{@code pkcs8.b64 = ...} base64-encoded key</li>
     * </ul>
     *
     * @param spec specification to marshal
     * @return serialized representation containing the base64-encoded key
     */
    public static PairSeq marshal(SntruPrimePrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "SntruPrimePrivateKeySpec", PKCS8_B64, b64);
    }

    /**
     * Reconstructs a private key specification from a {@link PairSeq}.
     *
     * <p>
     * The sequence must contain a {@code pkcs8.b64} entry; otherwise an
     * {@link IllegalArgumentException} is thrown.
     * </p>
     *
     * @param p serialized pair sequence produced by
     *          {@link #marshal(SntruPrimePrivateKeySpec)}
     * @return a new specification with the decoded PKCS#8 bytes
     * @throws IllegalArgumentException if the required field is missing
     */
    public static SntruPrimePrivateKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (PKCS8_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("SntruPrimePrivateKeySpec: missing pkcs8.b64");
        }
        byte[] decoded = Base64.getDecoder().decode(b64);
        try {
            return new SntruPrimePrivateKeySpec(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Returns a diagnostic string identifying this specification.
     *
     * <p>
     * The string includes the encoded key length but never the key material.
     * </p>
     *
     * @return a string such as {@code "SntruPrimePrivateKeySpec[len=1234]"}
     */
    @Override
    public String toString() {
        return "SntruPrimePrivateKeySpec[len=" + pkcs8.length + "]";
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
            throw new IllegalStateException("SNTRU Prime private key specification has been destroyed");
        }
    }
}
