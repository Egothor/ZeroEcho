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
package zeroecho.core.alg.hqc;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>HQC Private Key Specification</h2>
 *
 * {@link zeroecho.core.spec.AlgorithmKeySpec} wrapper for HQC private keys,
 * encoded in standard PKCS#8 DER format.
 *
 * <p>
 * This class is used to transport and import HQC private keys into the
 * {@link HqcAlgorithm}. The encoded form is defensively copied on construction
 * and retrieval and may be destroyed.
 * </p>
 *
 * <h2>Serialization</h2>
 * <p>
 * {@link #marshal(HqcPrivateKeySpec)} encodes the key material into a
 * {@link PairSeq} with Base64 (unpadded) representation. The inverse
 * {@link #unmarshal(PairSeq)} restores the specification from such a sequence.
 * </p>
 *
 * <h2>Security note</h2>
 * <ul>
 * <li>The contained byte array represents sensitive key material. Applications
 * should minimize retention and ensure secure erasure when possible.</li>
 * <li>Use only for import into a trusted {@link java.security.KeyFactory} or
 * {@link HqcAlgorithm}. Never log or transmit the raw array.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Wrap an existing PKCS#8 HQC private key
 * HqcPrivateKeySpec spec = new HqcPrivateKeySpec(pkcs8Bytes);
 *
 * // Import into a PrivateKey via HqcAlgorithm
 * HqcAlgorithm hqc = new HqcAlgorithm();
 * PrivateKey priv = hqc.privateKeyImporter(HqcPrivateKeySpec.class).importPrivate(spec);
 *
 * // Serialize for transport
 * PairSeq serialized = HqcPrivateKeySpec.marshal(spec);
 *
 * // Reconstruct from serialized form
 * HqcPrivateKeySpec restored = HqcPrivateKeySpec.unmarshal(serialized);
 * }</pre>
 *
 * @since 1.0
 */
public final class HqcPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a new private key spec from a PKCS#8-encoded byte array.
     *
     * @param pkcs8Der DER-encoded PKCS#8 private key
     * @throws NullPointerException if {@code pkcs8Der} is {@code null}
     */
    public HqcPrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der).clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded key material.
     *
     * @return cloned PKCS#8 byte array
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
     * Serializes this spec into a {@link PairSeq} with Base64-encoded key data.
     *
     * <p>
     * The resulting sequence has keys:
     * <ul>
     * <li>{@code type} = {@code "HqcPrivateKeySpec"}</li>
     * <li>{@code pkcs8.b64} = Base64 of the PKCS#8 key</li>
     * </ul>
     *
     * @param spec the spec to serialize
     * @return serialized representation in a {@link PairSeq}
     */
    public static PairSeq marshal(HqcPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "HqcPrivateKeySpec", PKCS8_B64, b64);
    }

    /**
     * Reconstructs a spec from its {@link PairSeq} representation.
     *
     * @param p sequence containing {@code pkcs8.b64}
     * @return reconstructed {@code HqcPrivateKeySpec}
     * @throws IllegalArgumentException if required field {@code pkcs8.b64} is
     *                                  missing
     */
    public static HqcPrivateKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (PKCS8_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("HqcPrivateKeySpec: missing pkcs8.b64");
        }
        byte[] decoded = Base64.getDecoder().decode(b64);
        try {
            return new HqcPrivateKeySpec(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Returns a diagnostic string containing the encoded length.
     *
     * <p>
     * The actual key material is not exposed in this representation.
     * </p>
     *
     * @return string with the PKCS#8 byte length
     */
    @Override
    public String toString() {
        return "HqcPrivateKeySpec[len=" + pkcs8.length + "]";
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
            throw new IllegalStateException("HQC private key specification has been destroyed");
        }
    }
}
