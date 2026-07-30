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

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMExtractor;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKEMGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * KEM context for SNTRU Prime that performs encapsulation and decapsulation
 * using the underlying key material.
 *
 * <h2>Overview</h2> Instances of this context are initialized either for
 * encapsulation with a recipient {@link java.security.PublicKey} or for
 * decapsulation with a holder {@link java.security.PrivateKey}. The role is
 * fixed at construction time.
 * <ul>
 * <li>Encapsulation: generates a fresh shared secret and its corresponding
 * ciphertext.</li>
 * <li>Decapsulation: derives the shared secret from a provided ciphertext.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Encapsulation side (initiator)
 * KemContext enc = new SntruPrimeKemContext(algorithm, recipientPublicKey);
 * KemResult kem = enc.encapsulate();
 * byte[] ct = kem.ciphertext();
 * byte[] secret = kem.sharedSecret();
 *
 * // Decapsulation side (responder)
 * KemContext dec = new SntruPrimeKemContext(algorithm, myPrivateKey);
 * byte[] secret2 = dec.decapsulate(ct);
 * }</pre>
 *
 * @see KemContext
 * @see SntruPrimeAlgorithm
 */
public final class SntruPrimeKemContext implements KemContext {
    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Creates an encapsulation context bound to a recipient public key.
     *
     * @param algorithm the owning algorithm that defines provider and naming
     *                  conventions; must not be null
     * @param k         the recipient public key used to encapsulate to; must not be
     *                  null
     * @throws NullPointerException if {@code algorithm} or {@code k} is null
     */
    public SntruPrimeKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = true;
    }

    /**
     * Creates a decapsulation context bound to a holder private key.
     *
     * @param algorithm the owning algorithm that defines provider and naming
     *                  conventions; must not be null
     * @param k         the private key used to decapsulate ciphertexts; must not be
     *                  null
     * @throws NullPointerException if {@code algorithm} or {@code k} is null
     */
    public SntruPrimeKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = false;
    }

    /**
     * Returns the algorithm that owns this context.
     *
     * @return the associated algorithm
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * <p>
     * For encapsulation this is a {@link java.security.PublicKey}. For
     * decapsulation this is a {@link java.security.PrivateKey}.
     * </p>
     *
     * @return the bound key
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes this context and releases any resources.
     *
     * <p>
     * This implementation has no external resources to release and is a no-op.
     * </p>
     */
    @Override
    public void close() {
        // empty
    }

    /**
     * Generates a fresh shared secret and its ciphertext using the recipient public
     * key.
     *
     * <p>
     * This method may only be called on contexts constructed for encapsulation. If
     * the context was constructed with a private key, an
     * {@code IllegalStateException} is thrown.
     * </p>
     *
     * @return a KEM result containing the ciphertext and the derived shared secret
     * @throws IllegalStateException if this context is not initialized for
     *                               encapsulation
     * @throws IOException           if the underlying provider fails to perform
     *                               encapsulation
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            final SNTRUPrimePublicKeyParameters keyParam = (SNTRUPrimePublicKeyParameters) PublicKeyFactory
                    .createKey(key.getEncoded());
            SNTRUPrimeKEMGenerator gen = new SNTRUPrimeKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(keyParam);
            byte[] secret = Arrays.copyOf(res.getSecret(), res.getSecret().length);
            byte[] ct = Arrays.copyOf(res.getEncapsulation(), res.getEncapsulation().length);
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("SNTRUPrime encapsulate failed", e);
        }
    }

    /**
     * Derives the shared secret from the provided ciphertext using the holder
     * private key.
     *
     * <p>
     * This method may only be called on contexts constructed for decapsulation. If
     * the context was constructed with a public key, an
     * {@code IllegalStateException} is thrown.
     * </p>
     *
     * @param ciphertext the KEM ciphertext produced by encapsulation
     * @return the derived shared secret bytes
     * @throws NullPointerException  if {@code ciphertext} is null
     * @throws IllegalStateException if this context is not initialized for
     *                               decapsulation
     * @throws IOException           if the underlying provider fails to perform
     *                               decapsulation
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        try {
            final SNTRUPrimePrivateKeyParameters keyParam = (SNTRUPrimePrivateKeyParameters) PrivateKeyFactory
                    .createKey(key.getEncoded());
            SNTRUPrimeKEMExtractor ex = new SNTRUPrimeKEMExtractor(keyParam);
            return ex.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("SNTRUPrime decapsulate failed", e);
        }
    }
}
