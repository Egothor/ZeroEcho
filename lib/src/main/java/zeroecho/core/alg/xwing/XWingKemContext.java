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

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMExtractor;
import org.bouncycastle.pqc.crypto.xwing.XWingKEMGenerator;
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.xwing.XWingPublicKeyParameters;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * KEM context for the X-Wing hybrid post-quantum key encapsulation mechanism.
 *
 * <p>
 * X-Wing combines X25519 (classical) and ML-KEM-768 (post-quantum) into a
 * single hybrid KEM as specified in
 * <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/">
 * draft-connolly-cfrg-xwing-kem</a>. It provides security if either component
 * is secure.
 * </p>
 *
 * <p>
 * Because there is no JCA provider binding for X-Wing in BouncyCastle 1.86,
 * this context uses the low-level BC API ({@code pqc.crypto.xwing.*}) directly.
 * The keys must therefore be instances of {@link XWingPublicKey} (encapsulate
 * mode) or {@link XWingPrivateKey} (decapsulate mode) as produced by
 * {@link XWingAlgorithm}.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <p>
 * Instances are not thread-safe. Sequential operations in the configured role
 * are supported while the borrowed key remains usable; no single-use guard is
 * maintained. Closing this context does not destroy the borrowed key.
 * </p>
 *
 * @since 1.0
 */
public final class XWingKemContext implements KemContext {

    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Creates a context in encapsulation role bound to the given public key.
     *
     * @param algorithm the owning algorithm instance; must not be {@code null}
     * @param k         an {@link XWingPublicKey}; must not be {@code null}
     * @throws NullPointerException if any argument is {@code null}
     * @throws IllegalArgumentException if the key is not an imported or generated X-Wing public key
     */
    public XWingKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        if (!(k instanceof XWingPublicKey)) {
            throw new IllegalArgumentException("Expected an X-Wing public key");
        }
        // The package-private key constructor enforces the fixed encoded length.
        this.encapsulate = true;
    }

    /**
     * Creates a context in decapsulation role bound to the given private key.
     *
     * @param algorithm the owning algorithm instance; must not be {@code null}
     * @param k         an {@link XWingPrivateKey}; must not be {@code null}
     * @throws NullPointerException if any argument is {@code null}
     * @throws IllegalArgumentException if the key is not an imported or generated X-Wing private key
     * @throws IllegalStateException if the private key was destroyed
     */
    public XWingKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        if (!(k instanceof XWingPrivateKey privateKey)) {
            throw new IllegalArgumentException("Expected an X-Wing private key");
        }
        if (privateKey.isDestroyed()) {
            throw new IllegalStateException("X-Wing private key has been destroyed");
        }
        this.encapsulate = false;
    }

    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    @Override
    public Key key() {
        return key;
    }

    @Override
    public void close() {
        // empty
    }

    /**
     * Encapsulates a fresh shared secret to the recipient's X-Wing public key.
     *
     * @return ciphertext and shared secret
     * @throws IllegalStateException if this context is in decapsulation mode
     * @throws IOException           if encapsulation fails
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            XWingPublicKeyParameters params = new XWingPublicKeyParameters(((XWingPublicKey) key).rawEncoded());
            XWingKEMGenerator gen = new XWingKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(params);
            byte[] secret = Arrays.copyOf(res.getSecret(), res.getSecret().length);
            byte[] ct = Arrays.copyOf(res.getEncapsulation(), res.getEncapsulation().length);
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("X-Wing encapsulate failed", e);
        }
    }

    /**
     * Decapsulates an X-Wing ciphertext using the bound private key.
     *
     * @param ciphertext the encapsulated bytes produced by the peer's
     *                   {@link #encapsulate()} call
     * @return the recovered shared secret
     * @throws IllegalStateException if this context is in encapsulation mode
     * @throws IOException           if decapsulation fails
     * @throws IllegalArgumentException if the ciphertext is null or not exactly 1120 bytes
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        if (ciphertext == null || ciphertext.length != 1120) {
            throw new IllegalArgumentException("X-Wing ciphertext must contain exactly 1120 bytes");
        }
        byte[] seed = null;
        try {
            seed = ((XWingPrivateKey) key).rawSeed();
            XWingPrivateKeyParameters params = new XWingPrivateKeyParameters(seed);
            XWingKEMExtractor ext = new XWingKEMExtractor(params);
            return ext.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("X-Wing decapsulate failed", e);
        } finally {
            if (seed != null) {
                Arrays.fill(seed, (byte) 0);
            }
        }
    }
}
