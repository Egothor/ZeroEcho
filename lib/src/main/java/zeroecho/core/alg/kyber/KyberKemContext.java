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
package zeroecho.core.alg.kyber;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * KyberKemContext is a lightweight KEM context used to perform Kyber (ML-KEM)
 * encapsulation or decapsulation.
 *
 * <h2>Overview</h2> A context is created in exactly one role:
 * <ul>
 * <li>Encapsulation role when constructed with a {@link PublicKey}. In this
 * role {@link #encapsulate()} is enabled and {@link #decapsulate(byte[])} is
 * invalid.</li>
 * <li>Decapsulation role when constructed with a {@link PrivateKey}. In this
 * role {@link #decapsulate(byte[])} is enabled and {@link #encapsulate()} is
 * invalid.</li>
 * </ul>
 * The implementation delegates to Bouncy Castle PQC primitives for ML-KEM. The
 * context retains a reference to the associated {@link CryptoAlgorithm}
 * instance to report metadata via {@link #algorithm()}.
 *
 * <h2>Thread-safety</h2> Instances are not explicitly synchronized. Do not
 * share a single context instance across threads while operations are running.
 *
 * <h2>Usage examples</h2> <pre>{@code
 * // Encapsulation role (sender knows recipient's public key):
 * KemContext encCtx = new KyberKemContext(alg, recipientPublicKey);
 * KemResult result = encCtx.encapsulate();
 * byte[] ciphertext = result.ciphertext();
 * byte[] sharedSecret = result.sharedSecret();
 *
 * // Decapsulation role (recipient uses its private key):
 * KemContext decCtx = new KyberKemContext(alg, recipientPrivateKey);
 * byte[] agreedSecret = decCtx.decapsulate(ciphertext);
 * }</pre>
 */
public final class KyberKemContext implements KemContext {

    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Creates a context in encapsulation role bound to the given public key.
     *
     * @param algorithm the owning algorithm instance that exposes provider name and
     *                  metadata; must not be null.
     * @param k         the recipient public key for encapsulation; must not be
     *                  null.
     * @throws NullPointerException if any argument is null.
     */
    public KyberKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.key = Objects.requireNonNull(k, "public key must not be null");
        this.encapsulate = true;
    }

    /**
     * Creates a context in decapsulation role bound to the given private key.
     *
     * @param algorithm the owning algorithm instance that exposes provider name and
     *                  metadata; must not be null.
     * @param k         the local private key for decapsulation; must not be null.
     * @throws NullPointerException if any argument is null.
     */
    public KyberKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm must not be null");
        this.key = Objects.requireNonNull(k, "private key must not be null");
        this.encapsulate = false;
    }

    /**
     * Returns the algorithm descriptor associated with this context.
     *
     * @return the algorithm that created this context.
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * @return the public key when in encapsulation role, or the private key when in
     *         decapsulation role.
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes this context.
     *
     * <p>
     * This implementation does not hold external resources, so the method is a
     * no-op. It is provided for API symmetry and future compatibility.
     * </p>
     */
    @Override
    public void close() {
        // empty
    }

    /**
     * Performs Kyber encapsulation using the bound public key and returns the
     * ciphertext and shared secret.
     *
     * <p>
     * This method is valid only if the context was constructed with a
     * {@link PublicKey}. If the context is in decapsulation role, an
     * {@link IllegalStateException} is thrown.
     * </p>
     *
     * @return a result containing the encapsulated ciphertext and the derived
     *         shared secret.
     * @throws IllegalStateException if the context is not initialized for
     *                               encapsulation.
     * @throws IOException           if encapsulation fails in the underlying
     *                               provider.
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            final MLKEMPublicKeyParameters keyParam = (MLKEMPublicKeyParameters) PublicKeyFactory
                    .createKey(key.getEncoded());
            MLKEMGenerator gen = new MLKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(keyParam);
            byte[] secret = Arrays.copyOf(res.getSecret(), res.getSecret().length);
            byte[] ct = Arrays.copyOf(res.getEncapsulation(), res.getEncapsulation().length);
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("Kyber encapsulate failed", e);
        }
    }

    /**
     * Performs Kyber decapsulation using the bound private key and returns the
     * shared secret.
     *
     * <p>
     * This method is valid only if the context was constructed with a
     * {@link PrivateKey}. If the context is in encapsulation role, an
     * {@link IllegalStateException} is thrown.
     * </p>
     *
     * @param ciphertext the Kyber ciphertext to decapsulate; must be the exact
     *                   bytes produced by the peer's encapsulate call.
     * @return the derived shared secret corresponding to the provided ciphertext.
     * @throws IllegalStateException if the context is not initialized for
     *                               decapsulation.
     * @throws IOException           if decapsulation fails in the underlying
     *                               provider.
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        try {
            final MLKEMPrivateKeyParameters keyParam = (MLKEMPrivateKeyParameters) PrivateKeyFactory
                    .createKey(key.getEncoded());
            MLKEMExtractor gen = new MLKEMExtractor(keyParam);

            return gen.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("Kyber decapsulate failed", e);
        }
    }
}
