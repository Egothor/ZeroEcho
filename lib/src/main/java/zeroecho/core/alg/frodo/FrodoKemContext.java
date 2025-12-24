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
package zeroecho.core.alg.frodo;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMExtractor;
import org.bouncycastle.pqc.crypto.frodo.FrodoKEMGenerator;
import org.bouncycastle.pqc.crypto.frodo.FrodoPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.frodo.FrodoPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * <h2>FrodoKEM runtime context</h2>
 *
 * Implementation of {@link zeroecho.core.context.KemContext} for the Frodo
 * post-quantum key encapsulation mechanism (KEM).
 *
 * <p>
 * A {@code FrodoKemContext} is a lightweight binding of:
 * </p>
 * <ul>
 * <li>a {@link zeroecho.core.CryptoAlgorithm} descriptor,</li>
 * <li>a key (public for encapsulation or private for decapsulation), and</li>
 * <li>a role indicator (encapsulate or decapsulate).</li>
 * </ul>
 *
 * <p>
 * Contexts are created by {@link FrodoAlgorithm} when binding roles such as
 * {@link zeroecho.core.KeyUsage#ENCAPSULATE} or
 * {@link zeroecho.core.KeyUsage#DECAPSULATE}. They provide the runtime entry
 * points to encapsulate a secret or decapsulate a received ciphertext.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are not thread-safe. A context is intended for single-operation or
 * short-lived use within a single thread.
 * </p>
 *
 * @since 1.0
 */
public final class FrodoKemContext implements KemContext {
    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Constructs a context bound to a public key for the
     * {@link zeroecho.core.KeyUsage#ENCAPSULATE} role.
     *
     * @param algorithm algorithm descriptor, must not be {@code null}
     * @param k         Frodo public key used to encapsulate the shared secret
     * @throws NullPointerException if any argument is {@code null}
     */
    public FrodoKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = true;
    }

    /**
     * Constructs a context bound to a private key for the
     * {@link zeroecho.core.KeyUsage#DECAPSULATE} role.
     *
     * @param algorithm algorithm descriptor, must not be {@code null}
     * @param k         Frodo private key used to decapsulate ciphertext
     * @throws NullPointerException if any argument is {@code null}
     */
    public FrodoKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = false;
    }

    /**
     * Returns the associated algorithm descriptor.
     *
     * @return algorithm instance that created this context
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * @return public key (for encapsulate) or private key (for decapsulate)
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes the context and releases any held resources.
     *
     * <p>
     * For FrodoKEM this is a no-op, but the method is present for consistency with
     * other context types.
     * </p>
     */
    @Override
    public void close() {
        // empty
    }

    /**
     * Encapsulates a fresh shared secret to the recipient’s public key.
     *
     * <p>
     * This method is only valid if the context was constructed with a public key
     * (encapsulation role). Otherwise an {@link IllegalStateException} is thrown.
     * </p>
     *
     * <p>
     * A new random secret and ciphertext are generated using BouncyCastle’s
     * FrodoKEM implementation. The ciphertext is transmitted to the recipient,
     * while the secret is retained locally as the agreed keying material.
     * </p>
     *
     * @return result containing the encapsulated ciphertext and shared secret
     * @throws IllegalStateException if this context is in decapsulation mode
     * @throws IOException           if encapsulation fails in the underlying
     *                               provider
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            final FrodoPublicKeyParameters keyParam = (FrodoPublicKeyParameters) PublicKeyFactory
                    .createKey(key.getEncoded());
            FrodoKEMGenerator gen = new FrodoKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(keyParam);
            byte[] secret = res.getSecret();
            byte[] ct = res.getEncapsulation();
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("Frodo encapsulate failed", e);
        }
    }

    /**
     * Decapsulates a ciphertext to recover the shared secret.
     *
     * <p>
     * This method is only valid if the context was constructed with a private key
     * (decapsulation role). Otherwise an {@link IllegalStateException} is thrown.
     * </p>
     *
     * @param ciphertext encapsulated keying material received from the initiator
     * @return the recovered shared secret
     * @throws IllegalStateException if this context is in encapsulation mode
     * @throws IOException           if decapsulation fails in the underlying
     *                               provider
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        try {
            final FrodoPrivateKeyParameters keyParam = (FrodoPrivateKeyParameters) PrivateKeyFactory
                    .createKey(key.getEncoded());
            FrodoKEMExtractor ex = new FrodoKEMExtractor(keyParam);
            return ex.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("Frodo decapsulate failed", e);
        }
    }
}
