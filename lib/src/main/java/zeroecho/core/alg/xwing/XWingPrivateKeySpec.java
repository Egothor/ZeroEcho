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
package zeroecho.core.alg.xwing;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.marshal.PairSeq.Cursor;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded representation of an X-Wing private key as its 32-byte seed.
 *
 * <p>
 * X-Wing uses a raw seed encoding for private keys (no DER/PKCS#8), as
 * BouncyCastle 1.86 has no JCA/JCE provider binding for X-Wing. The seed
 * allows deterministic reconstruction of the full X-Wing private key via
 * {@link org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters}.
 * </p>
 *
 * <p>
 * This class implements {@link Destroyable} to allow zeroing of key material
 * when the spec is no longer needed.
 * </p>
 *
 * @since 1.0
 */
public final class XWingPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private static final String SEED_B64 = "seed.b64";
    /* default */ static final int SEED_LENGTH = 32;
    private final byte[] seed;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private boolean destroyed;

    /**
     * Constructs a new spec from a raw X-Wing private key seed.
     *
     * @param seed 32-byte private key seed
     * @throws NullPointerException if {@code seed} is null
     * @throws IllegalArgumentException if the seed is not exactly 32 bytes
     */
    public XWingPrivateKeySpec(byte[] seed) {
        Objects.requireNonNull(seed, "seed");
        if (seed.length != SEED_LENGTH) {
            throw new IllegalArgumentException("X-Wing private seed must contain exactly 32 bytes");
        }
        this.seed = Objects.requireNonNull(seed).clone();
    }

    /**
     * Returns a defensive copy of the raw seed bytes.
     *
     * @return seed bytes
     * @throws IllegalStateException if this spec has been destroyed
     */
    public byte[] rawSeed() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return seed.clone();
        } finally {
            lifecycleLock.unlock();
        }
    }

    /**
     * Serializes this spec to a {@link PairSeq}.
     *
     * @param spec the spec to serialize
     * @return serialized representation
     */
    public static PairSeq marshal(XWingPrivateKeySpec spec) {
        return PairSeq.of("type", "XWingPrivateKeySpec", SEED_B64, spec.encodedSeed());
    }

    /**
     * Deserializes a spec from a {@link PairSeq}.
     *
     * @param p serialized representation
     * @return reconstructed spec
     * @throws IllegalArgumentException if required field is missing
     */
    public static XWingPrivateKeySpec unmarshal(PairSeq p) {
        String b64 = null;
        for (Cursor cur = p.cursor(); cur.next();) {
            if (SEED_B64.equals(cur.key())) {
                b64 = cur.value();
            }
        }
        if (b64 == null) {
            throw new IllegalArgumentException("XWingPrivateKeySpec: missing seed.b64");
        }
        if (b64.length() != 43 && b64.length() != 44) {
            throw new IllegalArgumentException("XWingPrivateKeySpec: invalid encoded length");
        }
        byte[] decoded = Base64.getDecoder().decode(b64);
        try {
            return new XWingPrivateKeySpec(decoded);
        } finally {
            Arrays.fill(decoded, (byte) 0);
        }
    }

    @Override
    public void destroy() {
        lifecycleLock.lock();
        try {
            if (!destroyed) {
                Arrays.fill(seed, (byte) 0);
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

    @Override
    public String toString() {
        return "XWingPrivateKeySpec[len=" + seed.length + "]";
    }

    private String encodedSeed() {
        lifecycleLock.lock();
        try {
            ensureActive();
            return Base64.getEncoder().withoutPadding().encodeToString(seed);
        } finally {
            lifecycleLock.unlock();
        }
    }

    private void ensureActive() {
        if (destroyed) {
            throw new IllegalStateException("X-Wing private key specification has been destroyed");
        }
    }
}
