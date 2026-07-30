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
package zeroecho.core.alg.mldsa;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded representation of an ML-DSA private key.
 *
 * <p>
 * {@code MldsaPrivateKeySpec} is a destroyable value object that wraps a
 * PKCS#8-encoded ML-DSA private key together with the JCA provider name that
 * should be used when importing the key.
 * </p>
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>The private key material is stored as a defensive copy of the provided
 * PKCS#8 byte array.</li>
 * <li>Marshalling/unmarshalling uses {@link PairSeq} with Base64 encoding under
 * {@code "pkcs8.b64"}.</li>
 * </ul>
 *
 * <h2>Provider selection</h2>
 * <p>
 * The default provider is {@code "BC"}.
 * </p>
 *
 * @since 1.0
 */
public final class MldsaPrivateKeySpec implements AlgorithmKeySpec, Destroyable {

    private final byte[] encodedPkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final String providerName;
    private boolean destroyed;

    /**
     * Creates a new specification using the default provider {@code "BC"}.
     *
     * @param encodedPkcs8 PKCS#8-encoded ML-DSA private key bytes
     * @throws IllegalArgumentException if {@code encodedPkcs8} is {@code null}
     */
    public MldsaPrivateKeySpec(byte[] encodedPkcs8) {
        this(encodedPkcs8, "BC");
    }

    /**
     * Creates a new specification using the supplied provider.
     *
     * @param encodedPkcs8 PKCS#8-encoded ML-DSA private key bytes
     * @param providerName JCA provider name to use for import; may be {@code null}
     * @throws IllegalArgumentException if {@code encodedPkcs8} is {@code null}
     */
    public MldsaPrivateKeySpec(byte[] encodedPkcs8, String providerName) {
        if (encodedPkcs8 == null) {
            throw new IllegalArgumentException("encodedPkcs8 must not be null");
        }
        this.encodedPkcs8 = encodedPkcs8.clone();
        this.providerName = (providerName == null ? "BC" : providerName);
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded private key bytes.
     *
     * @return a copy of the encoded private key
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
     * Returns the provider name associated with this specification.
     *
     * @return provider name, never {@code null}
     */
    public String providerName() {
        return providerName;
    }

    /**
     * Serializes the given spec into a {@link PairSeq}.
     *
     * @param spec the private key specification to serialize
     * @return serialized representation
     * @throws NullPointerException if {@code spec} is {@code null}
     */
    public static PairSeq marshal(MldsaPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "MLDSA-PRIV", "pkcs8.b64", b64, "provider", spec.providerName);
    }

    /**
     * Deserializes a {@link MldsaPrivateKeySpec} from a {@link PairSeq}.
     *
     * @param p serialized input
     * @return reconstructed private key specification
     * @throws IllegalArgumentException if {@code "pkcs8.b64"} is missing
     * @throws NullPointerException     if {@code p} is {@code null}
     */
    public static MldsaPrivateKeySpec unmarshal(PairSeq p) {
        byte[] out = null;
        String prov = "BC";
        try {
            PairSeq.Cursor c = p.cursor();
            while (c.next()) {
                String k = c.key();
                String v = c.value();
                switch (k) {
                    case "pkcs8.b64" -> out = decodeReplacing(out, v);
                    case "provider" -> prov = v;
                    default -> {
                    }
                }
            }
            if (out == null) {
                throw new IllegalArgumentException("pkcs8.b64 missing for ML-DSA private key");
            }
            return new MldsaPrivateKeySpec(out, prov);
        } finally {
            wipe(out);
        }
    }

    private static byte[] decodeReplacing(byte[] current, String encoded) {
        wipe(current);
        return Base64.getDecoder().decode(encoded);
    }

    private static void wipe(byte[] current) {
        if (current != null) {
            Arrays.fill(current, (byte) 0);
        }
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
            throw new IllegalStateException("ML-DSA private key specification has been destroyed");
        }
    }
}
