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
package zeroecho.core.alg.ntru;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMExtractor;
import org.bouncycastle.pqc.crypto.ntru.NTRUKEMGenerator;
import org.bouncycastle.pqc.crypto.ntru.NTRUPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntru.NTRUPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * NtruKemContext performs NTRU key encapsulation and decapsulation against a
 * single key and parameter set.
 *
 * <p>
 * This context is created either with a public key (encapsulation role) or a
 * private key (decapsulation role) and then drives the NTRU KEM using Bouncy
 * Castle's lightweight API under the hood. Public keys enable
 * {@link #encapsulate()}, private keys enable {@link #decapsulate(byte[])}.
 * Calling a method that does not match the role results in
 * {@link IllegalStateException}.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Key generation and import are outside of this class; shown here for completeness.
 * KeyPairGenerator kpg = KeyPairGenerator.getInstance("NTRU", "BCPQC");
 * kpg.initialize(NTRUParameterSpec.ntruhrss701, new SecureRandom());
 * KeyPair kp = kpg.generateKeyPair();
 *
 * // Initiator (encapsulation) uses the recipient's public key
 * try (NtruKemContext enc = new NtruKemContext(algorithm, kp.getPublic())) {
 *     KemContext.KemResult r = enc.encapsulate();
 *     byte[] ct = r.ciphertext();     // message to send to the recipient
 *     byte[] ssA = r.sharedSecret();  // initiator's shared secret
 *
 *     // Responder (decapsulation) uses the matching private key
 *     try (NtruKemContext dec = new NtruKemContext(algorithm, kp.getPrivate())) {
 *         byte[] ssB = dec.decapsulate(ct);
 *         // ssA and ssB are identical
 *     }
 * }
 * }</pre>
 *
 * <h2>Key material and formats</h2>
 * <p>
 * The context consumes standard JCA keys via
 * {@link java.security.Key#getEncoded()}: X.509 SubjectPublicKeyInfo for public
 * keys and PKCS#8 PrivateKeyInfo for private keys. Internally these are
 * converted to Bouncy Castle NTRU key parameters for the KEM operations.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are not thread-safe. Create a separate context per thread or per
 * protocol run.
 * </p>
 *
 * @since 1.0
 */
public final class NtruKemContext implements KemContext {

    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Creates an encapsulation context bound to the provided public key.
     *
     * <p>
     * The resulting instance supports {@link #encapsulate()} and forbids
     * {@link #decapsulate(byte[])}.
     * </p>
     *
     * @param algorithm the catalog algorithm descriptor this context belongs to,
     *                  must not be null
     * @param k         the recipient's public key in the NTRU parameter set of
     *                  interest, must not be null
     * @throws NullPointerException if any argument is null
     */
    public NtruKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.key = Objects.requireNonNull(k, "public key");
        this.encapsulate = true;
    }

    /**
     * Creates a decapsulation context bound to the provided private key.
     *
     * <p>
     * The resulting instance supports {@link #decapsulate(byte[])} and forbids
     * {@link #encapsulate()}.
     * </p>
     *
     * @param algorithm the catalog algorithm descriptor this context belongs to,
     *                  must not be null
     * @param k         the private key matching the recipient's public key, must
     *                  not be null
     * @throws NullPointerException if any argument is null
     */
    public NtruKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
        this.key = Objects.requireNonNull(k, "private key");
        this.encapsulate = false;
    }

    /**
     * Returns the algorithm descriptor that created this context.
     *
     * @return the algorithm descriptor, never null
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key this context is bound to.
     *
     * <p>
     * For encapsulation this is a public key; for decapsulation it is the matching
     * private key.
     * </p>
     *
     * @return the bound key reference, never null
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Closes this context.
     *
     * <p>
     * There are no native resources to release in the current implementation, so
     * this method is a no-op. It exists to honor the {@link KemContext} contract
     * and to allow future implementations to free resources.
     * </p>
     */
    @Override
    public void close() {
        // empty
    }

    /**
     * Performs NTRU key encapsulation using the bound public key.
     *
     * <p>
     * On success, returns the encapsulation ciphertext and the derived shared
     * secret. The ciphertext must be delivered to the holder of the matching
     * private key, who can derive the same secret by calling
     * {@link #decapsulate(byte[])}.
     * </p>
     *
     * @return the encapsulation result containing ciphertext and shared secret
     * @throws IOException           if the underlying cryptographic operation fails
     * @throws IllegalStateException if this context was constructed for
     *                               decapsulation
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            final NTRUPublicKeyParameters keyParam = (NTRUPublicKeyParameters) PublicKeyFactory
                    .createKey(key.getEncoded());
            NTRUKEMGenerator gen = new NTRUKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(keyParam);
            byte[] secret = Arrays.copyOf(res.getSecret(), res.getSecret().length);
            byte[] ct = Arrays.copyOf(res.getEncapsulation(), res.getEncapsulation().length);
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("NTRU encapsulate failed", e);
        }
    }

    /**
     * Performs NTRU key decapsulation using the bound private key.
     *
     * <p>
     * The input must be a valid encapsulation ciphertext produced for the matching
     * public key and parameter set. On success, the returned byte array is the
     * shared secret that matches the secret produced during encapsulation.
     * </p>
     *
     * @param ciphertext the encapsulation ciphertext received from the initiator,
     *                   must not be null
     * @return the derived shared secret
     * @throws IOException           if the underlying cryptographic operation fails
     *                               or the ciphertext is invalid
     * @throws IllegalStateException if this context was constructed for
     *                               encapsulation
     * @throws NullPointerException  if {@code ciphertext} is null
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        try {
            final NTRUPrivateKeyParameters keyParam = (NTRUPrivateKeyParameters) PrivateKeyFactory
                    .createKey(key.getEncoded());
            NTRUKEMExtractor ex = new NTRUKEMExtractor(keyParam);
            return ex.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("NTRU decapsulate failed", e);
        }
    }
}
