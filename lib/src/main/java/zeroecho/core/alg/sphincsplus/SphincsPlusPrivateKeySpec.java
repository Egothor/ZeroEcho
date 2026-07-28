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
package zeroecho.core.alg.sphincsplus;

import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.locks.ReentrantLock;

import javax.security.auth.Destroyable;

import zeroecho.core.marshal.PairSeq;
import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * Encoded representation of a SPHINCS+ private key.
 *
 * <p>
 * {@code SphincsPlusPrivateKeySpec} wraps a PKCS#8-encoded SPHINCS+ private key
 * along with the provider name that should be used for import. It is a simple
 * destroyable holder designed for use with {@link SphincsPlusPrivateKeyBuilder}.
 * </p>
 *
 * <h2>Encoding</h2>
 * <ul>
 * <li>The key is stored as a defensive copy of the provided PKCS#8 byte
 * array.</li>
 * <li>Marshalling and unmarshalling methods convert between this object and a
 * {@link PairSeq} representation using Base64 encoding.</li>
 * <li>The {@code providerName} defaults to {@code "BCPQC"} (Bouncy Castle PQC
 * provider) if not explicitly supplied.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Access and destruction are synchronized. Defensive
 * copies are returned for all sensitive material.
 *
 * <h2>Example</h2> <pre>{@code
 * // Wrap a PKCS#8-encoded private key
 * byte[] pkcs8 = ...;
 * SphincsPlusPrivateKeySpec spec = new SphincsPlusPrivateKeySpec(pkcs8);
 *
 * // Import the key via the builder
 * PrivateKey priv = new SphincsPlusPrivateKeyBuilder().importPrivate(spec);
 *
 * // Serialize to PairSeq for transport or persistence
 * PairSeq seq = SphincsPlusPrivateKeySpec.marshal(spec);
 *
 * // Reconstruct from PairSeq
 * SphincsPlusPrivateKeySpec restored = SphincsPlusPrivateKeySpec.unmarshal(seq);
 * }</pre>
 *
 * @since 1.0
 */
public final class SphincsPlusPrivateKeySpec implements AlgorithmKeySpec, Destroyable {
    private final byte[] encodedPkcs8;
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final String providerName; // e.g. "BCPQC"
    private boolean destroyed;

    /**
     * Constructs a new specification with the default provider {@code "BCPQC"}.
     *
     * @param encodedPkcs8 PKCS#8-encoded SPHINCS+ private key bytes
     * @throws IllegalArgumentException if {@code encodedPkcs8} is {@code null}
     */
    public SphincsPlusPrivateKeySpec(byte[] encodedPkcs8) {
        this(encodedPkcs8, "BCPQC");
    }

    /**
     * Constructs a new specification with the given provider.
     *
     * @param encodedPkcs8 PKCS#8-encoded SPHINCS+ private key bytes
     * @param providerName JCA provider to use for import; if {@code null}, defaults
     *                     to {@code "BCPQC"}
     * @throws IllegalArgumentException if {@code encodedPkcs8} is {@code null}
     */
    public SphincsPlusPrivateKeySpec(byte[] encodedPkcs8, String providerName) {
        if (encodedPkcs8 == null) {
            throw new IllegalArgumentException("encodedPkcs8 must not be null");
        }
        this.encodedPkcs8 = encodedPkcs8.clone();
        this.providerName = (providerName == null ? "BCPQC" : providerName);
    }

    /**
     * Returns a defensive copy of the PKCS#8-encoded private key.
     *
     * @return clone of the encoded key bytes
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
     * Serializes this specification into a {@link PairSeq}.
     *
     * <p>
     * The key bytes are Base64-encoded under the key {@code "pkcs8.b64"}. The
     * provider name is stored under the key {@code "provider"}.
     * </p>
     *
     * @param spec private key spec to marshal
     * @return serialized {@link PairSeq} representation
     */
    public static PairSeq marshal(SphincsPlusPrivateKeySpec spec) {
        String b64 = spec.encodedKey();
        return PairSeq.of("type", "SPHINCSPLUS-PRIV", "pkcs8.b64", b64, "provider", spec.providerName);
    }

    /**
     * Deserializes a {@code SphincsPlusPrivateKeySpec} from a {@link PairSeq}.
     *
     * <p>
     * Expects keys {@code "pkcs8.b64"} (required, Base64 string) and
     * {@code "provider"} (optional, defaults to {@code "BCPQC"}).
     * </p>
     *
     * @param p serialized input
     * @return a reconstructed private key spec
     * @throws IllegalArgumentException if the encoded key is missing
     */
    public static SphincsPlusPrivateKeySpec unmarshal(PairSeq p) {
        byte[] out = null;
        String prov = "BCPQC";
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
                throw new IllegalArgumentException("pkcs8.b64 missing for SPHINCS+ private key");
            }
            return new SphincsPlusPrivateKeySpec(out, prov);
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
            throw new IllegalStateException("SPHINCS+ private key specification has been destroyed");
        }
    }
}
