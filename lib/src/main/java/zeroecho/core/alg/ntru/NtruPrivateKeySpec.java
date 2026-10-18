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
package zeroecho.core.alg.ntru;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * NtruPrivateKeySpec holds a PKCS#8-encoded NTRU private key and supports a
 * simple marshal/unmarshal form.
 *
 * <p>
 * The byte array provided to the constructor is defensively copied and
 * {@link #pkcs8()} returns a fresh clone on each call. Access and destruction
 * are synchronized.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Construct from existing PKCS#8 bytes
 * byte[] pkcs8Der = Files.readAllBytes(Path.of("ntru-private.der"));
 * NtruPrivateKeySpec spec = new NtruPrivateKeySpec(pkcs8Der);
 *
 * // Import into JCA (example provider alias shown)
 * KeyFactory kf = KeyFactory.getInstance("NTRU", "BCPQC");
 * PrivateKey sk = kf.generatePrivate(new PKCS8EncodedKeySpec(spec.pkcs8()));
 *
 * // Marshal to a compact name-value form (Base64 without padding)
 * PairSeq serialized = NtruPrivateKeySpec.marshal(spec);
 *
 * // Later or elsewhere, reconstruct the spec
 * NtruPrivateKeySpec restored = NtruPrivateKeySpec.unmarshal(serialized);
 * }</pre>
 *
 * @since 1.0
 */
public final class NtruPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String PKCS8_B64 = "pkcs8.b64";
    private final byte[] pkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Creates a new specification from PKCS#8-encoded bytes.
     *
     * <p>
     * The input array is not retained. A defensive copy is made and stored.
     * </p>
     *
     * @param pkcs8Der PKCS#8 DER bytes of the NTRU private key, must not be null
     * @throws NullPointerException if {@code pkcs8Der} is null
     */
    public NtruPrivateKeySpec(byte[] pkcs8Der) {
        this.pkcs8 = Objects.requireNonNull(pkcs8Der, "pkcs8Der").clone();
    }

    /**
     * Returns a copy of the PKCS#8-encoded private key.
     *
     * <p>
     * The returned array is a fresh clone. Callers may modify it without affecting
     * the spec.
     * </p>
     *
     * @return a new byte array containing the PKCS#8 DER encoding
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
     * Serializes this specification into a simple name-value sequence.
     *
     * <p>
     * The output contains:
     * <ul>
     * <li>{@code "type"} set to {@code "NtruPrivateKey"} for identification,
     * and</li>
     * <li>{@code "pkcs8.b64"} containing the PKCS#8 bytes encoded with Base64
     * without padding.</li>
     * </ul>
     * This format is suitable for lightweight persistence or interchange where a
     * compact textual representation is preferred.
     *
     * @param spec the specification to serialize, must not be null
     * @return a {@code PairSeq} carrying the serialized fields
     * @throws NullPointerException if {@code spec} is null
     */
    public static PairSeq marshal(NtruPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "NtruPrivateKey", PKCS8_B64, b64);
    }

    /**
     * Deserializes a specification from a name-value sequence produced by
     * {@link #marshal(NtruPrivateKeySpec)}.
     *
     * <p>
     * Fields not recognized by this implementation are ignored to allow forward
     * compatibility. The field {@code "pkcs8.b64"} is required and must contain
     * Base64 (no padding) of the PKCS#8 bytes.
     * </p>
     *
     * @param p the sequence to read
     * @return a new specification carrying the decoded PKCS#8 bytes
     * @throws IllegalArgumentException if the required {@code "pkcs8.b64"} field is
     *                                  absent
     * @throws NullPointerException     if {@code p} is null
     */
    public static NtruPrivateKeySpec unmarshal(PairSeq p) {
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
            throw new IllegalArgumentException("NtruPrivateKeySpec: missing 'pkcs8.b64'");
        }
        byte[] decoded = Base64.getDecoder().decode(pkcs8b64);
        try {
            return new NtruPrivateKeySpec(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    /**
     * Returns a short diagnostic string including the encoded length.
     *
     * @return a human-readable form such as {@code NtruPrivateKeySpec[len=...]}}
     */
    @Override
    public String toString() {
        return "NtruPrivateKeySpec[len=" + pkcs8.length + "]";
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
            throw new IllegalStateException("NTRU private key specification has been destroyed");
        }
    }
}
