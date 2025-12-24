/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.core.alg.bike;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.bike.BIKEKEMExtractor;
import org.bouncycastle.pqc.crypto.bike.BIKEKEMGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * <h2>BIKE Key Encapsulation Mechanism context</h2>
 *
 * Implements {@link zeroecho.core.context.KemContext} for the BIKE (Bit
 * Flipping Key Encapsulation) post-quantum algorithm. Encapsulation and
 * decapsulation flows are separated by constructor:
 * <ul>
 * <li>Construct with a {@link java.security.PublicKey} to create an
 * <b>encapsulation</b> context.</li>
 * <li>Construct with a {@link java.security.PrivateKey} to create a
 * <b>decapsulation</b> context.</li>
 * </ul>
 *
 * <h3>Usage</h3> <pre>{@code
 * BikeKemContext enc = new BikeKemContext(algo, recipientPubKey);
 * KemResult r = enc.encapsulate();
 *
 * BikeKemContext dec = new BikeKemContext(algo, myPrivateKey);
 * byte[] secret = dec.decapsulate(r.ciphertext());
 * }</pre>
 *
 * @since 1.0
 */
public final class BikeKemContext implements KemContext {
    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Creates an encapsulation context bound to the recipient's public key.
     *
     * @param algorithm parent algorithm instance
     * @param k         recipient's public key
     * @throws NullPointerException if any argument is null
     */
    public BikeKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = true;
    }

    /**
     * Creates a decapsulation context bound to the holder's private key.
     *
     * @param algorithm parent algorithm instance
     * @param k         private key for decapsulation
     * @throws NullPointerException if any argument is null
     */
    public BikeKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = false;
    }

    /**
     * Returns the algorithm that created this context.
     *
     * @return parent algorithm
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the underlying key bound to this context.
     *
     * @return public or private key depending on mode
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Releases resources associated with this context.
     * <p>
     * No-op for BIKE; provided for API symmetry.
     * </p>
     */
    @Override
    public void close() {
        // empty
    }

    /**
     * Generates a new shared secret and ciphertext using the recipient's public
     * key.
     *
     * @return encapsulation result containing ciphertext and shared secret
     * @throws IOException           if encapsulation fails
     * @throws IllegalStateException if this context is not initialized for
     *                               encapsulation
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            final BIKEPublicKeyParameters keyParam = (BIKEPublicKeyParameters) PublicKeyFactory
                    .createKey(key.getEncoded());
            BIKEKEMGenerator gen = new BIKEKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(keyParam);
            byte[] secret = res.getSecret();
            byte[] ct = res.getEncapsulation();
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("BIKE encapsulate failed", e);
        }
    }

    /**
     * Recovers the shared secret from a ciphertext using the holder's private key.
     *
     * @param ciphertext encapsulated key material
     * @return recovered shared secret bytes
     * @throws IOException           if decapsulation fails
     * @throws IllegalStateException if this context is not initialized for
     *                               decapsulation
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        try {
            final BIKEPrivateKeyParameters keyParam = (BIKEPrivateKeyParameters) PrivateKeyFactory
                    .createKey(key.getEncoded());
            BIKEKEMExtractor ex = new BIKEKEMExtractor(keyParam);
            return ex.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("BIKE decapsulate failed", e);
        }
    }
}
