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
package zeroecho.core.alg.hqc;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMExtractor;
import org.bouncycastle.pqc.crypto.hqc.HQCKEMGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * <h2>HQC KEM Context</h2>
 *
 * Implementation of {@link zeroecho.core.context.KemContext} for the
 * post-quantum HQC (Hamming Quasi-Cyclic) key encapsulation mechanism.
 *
 * <p>
 * An {@code HqcKemContext} binds an HQC key (public or private) and role
 * (encapsulation or decapsulation). It delegates to BouncyCastle's
 * {@code HQCKEMGenerator} and {@code HQCKEMExtractor} for cryptographic
 * operations. This context is created indirectly via {@link HqcAlgorithm}, not
 * by application code.
 * </p>
 *
 * <h2>Roles</h2>
 * <ul>
 * <li><b>Encapsulation</b>: constructed with a {@link java.security.PublicKey}.
 * Provides {@link #encapsulate()} to generate a ciphertext and shared
 * secret.</li>
 * <li><b>Decapsulation</b>: constructed with a
 * {@link java.security.PrivateKey}. Provides {@link #decapsulate(byte[])} to
 * recover the shared secret from a ciphertext.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are not thread-safe. Each context should be used for a single
 * encapsulation or decapsulation flow.
 * </p>
 *
 * @since 1.0
 */
public final class HqcKemContext implements KemContext {
    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Constructs an encapsulation context using the recipient's public key.
     *
     * <p>
     * This role is for the initiator (Alice), who produces a ciphertext to send to
     * the responder.
     * </p>
     *
     * @param algorithm parent algorithm instance
     * @param k         HQC public key of the recipient
     * @throws NullPointerException if any argument is {@code null}
     */
    public HqcKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = true;
    }

    /**
     * Constructs a decapsulation context using the recipient's private key.
     *
     * <p>
     * This role is for the responder (Bob), who receives a ciphertext and recovers
     * the shared secret.
     * </p>
     *
     * @param algorithm parent algorithm instance
     * @param k         HQC private key of the recipient
     * @throws NullPointerException if any argument is {@code null}
     */
    public HqcKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = false;
    }

    /**
     * Returns the algorithm that created this context.
     *
     * @return associated {@link CryptoAlgorithm}
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the bound key (public or private) for this context.
     *
     * @return the underlying {@link Key} instance
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes this context. No-op for HQC, since no sensitive state is held beyond
     * the key reference.
     */
    @Override
    public void close() {
        // empty
    }

    /**
     * Performs HQC encapsulation, generating a ciphertext and a shared secret.
     *
     * <p>
     * Requires that the context was constructed with a public key. On success, a
     * {@link KemResult} containing the ciphertext and secret is returned.
     * </p>
     *
     * @return encapsulation result containing ciphertext and shared secret
     * @throws IOException           if encapsulation fails due to provider error
     * @throws IllegalStateException if this context was initialized for
     *                               decapsulation
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            final HQCPublicKeyParameters keyParam = (HQCPublicKeyParameters) PublicKeyFactory
                    .createKey(key.getEncoded());
            HQCKEMGenerator gen = new HQCKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(keyParam);
            byte[] secret = Arrays.copyOf(res.getSecret(), res.getSecret().length);
            byte[] ct = Arrays.copyOf(res.getEncapsulation(), res.getEncapsulation().length);
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("HQC encapsulate failed", e);
        }
    }

    /**
     * Performs HQC decapsulation, recovering the shared secret from a ciphertext.
     *
     * <p>
     * Requires that the context was constructed with a private key. On success, the
     * raw shared secret is returned.
     * </p>
     *
     * @param ciphertext the encapsulated key material produced by
     *                   {@link #encapsulate()}
     * @return the recovered shared secret
     * @throws IOException           if decapsulation fails due to provider error
     * @throws IllegalStateException if this context was initialized for
     *                               encapsulation
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        try {
            final HQCPrivateKeyParameters keyParam = (HQCPrivateKeyParameters) PrivateKeyFactory
                    .createKey(key.getEncoded());
            HQCKEMExtractor ex = new HQCKEMExtractor(keyParam);
            return ex.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("HQC decapsulate failed", e);
        }
    }
}
