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
package zeroecho.core.alg.saber;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.saber.SABERKEMExtractor;
import org.bouncycastle.pqc.crypto.saber.SABERKEMGenerator;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * KEM context for SABER supporting encapsulation with a public key and
 * decapsulation with a private key.
 *
 * <p>
 * A {@code SaberKemContext} is created in one of two roles:
 * </p>
 * <ul>
 * <li><b>Encapsulator</b>: constructed with a {@code PublicKey}, it produces an
 * encapsulation ciphertext and a fresh shared secret.</li>
 * <li><b>Decapsulator</b>: constructed with a {@code PrivateKey}, it derives
 * the shared secret from a received encapsulation ciphertext.</li>
 * </ul>
 *
 * <h2>Lifecycle and thread-safety</h2>
 * <p>
 * Instances are single-use per operation style and not thread-safe. Callers
 * should not share a context across threads without external synchronization.
 * {@link #close()} is a no-op because this context maintains no stream
 * resources.
 * </p>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Encapsulator side
 * KemContext enc = new SaberKemContext(algo, recipientPublicKey);
 * KemContext.KemResult r = enc.encapsulate();
 * byte[] ciphertext = r.ciphertext();
 * byte[] shared = r.sharedSecret();
 *
 * // Decapsulator side
 * KemContext dec = new SaberKemContext(algo, myPrivateKey);
 * byte[] shared2 = dec.decapsulate(ciphertext);
 * }</pre>
 */
public final class SaberKemContext implements KemContext {
    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Creates an encapsulation context bound to the recipient's {@link PublicKey}.
     *
     * @param algorithm the owning algorithm used for metadata and provider identity
     * @param k         recipient public key for SABER encapsulation
     * @throws NullPointerException if {@code algorithm} or {@code k} is
     *                              {@code null}
     */
    public SaberKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = true;
    }

    /**
     * Creates a decapsulation context bound to our {@link PrivateKey}.
     *
     * @param algorithm the owning algorithm used for metadata and provider identity
     * @param k         private key for SABER decapsulation
     * @throws NullPointerException if {@code algorithm} or {@code k} is
     *                              {@code null}
     */
    public SaberKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = false;
    }

    /**
     * Returns the algorithm that created this context.
     *
     * @return the associated {@link CryptoAlgorithm}
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * <p>
     * For encapsulation this is a {@link PublicKey}. For decapsulation this is a
     * {@link PrivateKey}.
     * </p>
     *
     * @return the bound {@link Key}
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes the context and releases resources.
     *
     * <p>
     * This implementation holds no stream resources, so the method is a no-op.
     * </p>
     */
    @Override
    public void close() {
        // empty
    }

    /**
     * Performs SABER encapsulation and returns the ciphertext and shared secret.
     *
     * <p>
     * This method is valid only when the context was constructed with a
     * {@link PublicKey}. The returned {@link KemResult} contains the encapsulation
     * to transmit and the derived shared secret.
     * </p>
     *
     * @return a {@link KemResult} holding the encapsulation and shared secret
     * @throws IllegalStateException if the context was initialized for
     *                               decapsulation
     * @throws IOException           if the underlying SABER operation fails
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            final SABERPublicKeyParameters keyParam = (SABERPublicKeyParameters) PublicKeyFactory
                    .createKey(key.getEncoded());
            SABERKEMGenerator gen = new SABERKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(keyParam);
            byte[] secret = Arrays.copyOf(res.getSecret(), res.getSecret().length);
            byte[] ct = Arrays.copyOf(res.getEncapsulation(), res.getEncapsulation().length);
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("SABER encapsulate failed", e);
        }
    }

    /**
     * Performs SABER decapsulation and returns the shared secret derived from
     * {@code ciphertext}.
     *
     * <p>
     * This method is valid only when the context was constructed with a
     * {@link PrivateKey}.
     * </p>
     *
     * @param ciphertext the peer's encapsulation ciphertext
     * @return the derived shared secret bytes
     * @throws IllegalStateException if the context was initialized for
     *                               encapsulation
     * @throws IOException           if the underlying SABER operation fails or
     *                               input is invalid
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        try {
            final SABERPrivateKeyParameters keyParam = (SABERPrivateKeyParameters) PrivateKeyFactory
                    .createKey(key.getEncoded());
            SABERKEMExtractor ex = new SABERKEMExtractor(keyParam);
            return ex.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("SABER decapsulate failed", e);
        }
    }
}
