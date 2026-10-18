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
package zeroecho.core.alg.elgamal;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>ElGamal Private Key Specification</h2>
 *
 * Wrapper for a PKCS#8-encoded ElGamal private key.
 *
 * <p>
 * This specification serves as the input to key-import routines, providing a
 * portable representation of private key material. The encoding format is
 * assumed to be PKCS#8 DER, as produced by standard JCA/JCE providers.
 * </p>
 *
 * <h2>Contents</h2>
 * <ul>
 * <li>{@link #encoded()} returns a defensive copy of the raw PKCS#8 bytes.</li>
 * <li>{@link #marshal(ElgamalPrivateKeySpec)} encodes the key into a
 * {@link PairSeq} structure for transport or logging.</li>
 * <li>{@link #unmarshal(PairSeq)} reconstructs the spec from a marshalled
 * representation.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Import from PKCS#8 DER
 * byte[] der = Files.readAllBytes(Path.of("elgamal-priv.der"));
 * ElgamalPrivateKeySpec spec = new ElgamalPrivateKeySpec(der);
 * PrivateKey priv = algo.privateKeyImporter(ElgamalPrivateKeySpec.class).importPrivate(spec);
 *
 * // Marshal for serialization
 * PairSeq ps = ElgamalPrivateKeySpec.marshal(spec);
 *
 * // Unmarshal back
 * ElgamalPrivateKeySpec restored = ElgamalPrivateKeySpec.unmarshal(ps);
 * }</pre>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Private key material must be protected in memory and at rest. The spec
 * itself does not attempt to zeroize its contents.</li>
 * <li>Always prefer secure storage (e.g., a hardware module) over raw byte
 * handling when possible.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Access and destruction are synchronized.
 *
 * @since 1.0
 */
public final class ElgamalPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a new private key spec from PKCS#8-encoded bytes.
     *
     * @param pkcs8 PKCS#8 DER encoding of the private key; must not be {@code null}
     */
    public ElgamalPrivateKeySpec(byte[] pkcs8) {
        this.pkcs8 = pkcs8.clone();
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded private key.
     *
     * @return PKCS#8 DER encoding
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
     * Serializes this spec into a {@link PairSeq}.
     *
     * <p>
     * The output includes:
     * <ul>
     * <li>{@code type} = {@code "ELGAMAL-PRIV"}</li>
     * <li>{@code pkcs8.b64} = Base64 encoding of the DER bytes (without
     * padding)</li>
     * </ul>
     *
     * @param spec ElGamal private key spec
     * @return marshalled key as {@link PairSeq}
     */
    public static PairSeq marshal(ElgamalPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "ELGAMAL-PRIV", PKCS8_B64, b64);
    }

    /**
     * Parses a {@link PairSeq} and reconstructs an {@code ElgamalPrivateKeySpec}.
     *
     * @param p encoded pair sequence
     * @return new private key spec
     * @throws IllegalArgumentException if required field {@code pkcs8.b64} is
     *                                  missing
     */
    public static ElgamalPrivateKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("pkcs8.b64 missing for ElGamal private key");
        }
        try {
            return new ElgamalPrivateKeySpec(out);
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
            throw new IllegalStateException("ElGamal private key specification has been destroyed");
        }
    }
}
