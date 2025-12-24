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
package zeroecho.core.alg.cmce;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Objects;

import javax.security.auth.DestroyFailedException;

import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.cmce.CMCEKEMExtractor;
import org.bouncycastle.pqc.crypto.cmce.CMCEKEMGenerator;
import org.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters;
import org.bouncycastle.pqc.crypto.util.PrivateKeyFactory;
import org.bouncycastle.pqc.crypto.util.PublicKeyFactory;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.context.KemContext;

/**
 * <h2>Classic McEliece (CMCE) KEM context</h2>
 *
 * <p>
 * Holds the state required to perform CMCE key encapsulation or decapsulation.
 * The operational mode is determined by the constructor used:
 * </p>
 *
 * <ul>
 * <li>PublicKey constructor - encapsulate mode</li>
 * <li>PrivateKey constructor - decapsulate mode</li>
 * </ul>
 *
 * <p>
 * Usage:
 * </p>
 * <pre>{@code
 * CryptoAlgorithm alg = ...;
 * PublicKey recipient = ...;
 *
 * // Encapsulation
 * try (CmceKemContext ctx = new CmceKemContext(alg, recipient)) {
 *   KemResult kem = ctx.encapsulate();
 *   byte[] ct = kem.ciphertext();
 *   byte[] secret = kem.secret();
 *   // send ct to recipient; use secret for key derivation
 * }
 *
 * // Decapsulation
 * PrivateKey myPriv = ...;
 * byte[] ct = ...;
 * try (CmceKemContext ctx = new CmceKemContext(alg, myPriv)) {
 *   byte[] secret = ctx.decapsulate(ct);
 * }
 * }</pre>
 *
 * <p>
 * Notes:
 * </p>
 * <ul>
 * <li>Encapsulation requires a CMCE public key; decapsulation requires a CMCE
 * private key.</li>
 * <li>Returned arrays are owned by the caller; callers should clear secrets
 * when no longer needed.</li>
 * <li>This class holds no external resources and is safe to close
 * repeatedly.</li>
 * </ul>
 *
 * @since 1.0
 */
public final class CmceKemContext implements KemContext {
    private final CryptoAlgorithm algorithm;
    private final Key key;
    private final boolean encapsulate;

    /**
     * Creates an encapsulation context bound to a recipient public key.
     *
     * @param algorithm parent algorithm metadata (for diagnostics)
     * @param k         CMCE public key
     * @throws NullPointerException if any argument is null
     */
    public CmceKemContext(CryptoAlgorithm algorithm, PublicKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = true;
    }

    /**
     * Creates a decapsulation context bound to a private key.
     *
     * @param algorithm parent algorithm metadata (for diagnostics)
     * @param k         CMCE private key
     * @throws NullPointerException if any argument is null
     */
    public CmceKemContext(CryptoAlgorithm algorithm, PrivateKey k) {
        this.algorithm = Objects.requireNonNull(algorithm);
        this.key = Objects.requireNonNull(k);
        this.encapsulate = false;
    }

    /**
     * Returns the parent algorithm descriptor for this context.
     *
     * @return algorithm descriptor; never null
     */
    @Override
    public CryptoAlgorithm algorithm() {
        return algorithm;
    }

    /**
     * Returns the key bound to this context.
     *
     * <p>
     * In encapsulate mode this is a {@link java.security.PublicKey}; in decapsulate
     * mode it is a {@link java.security.PrivateKey}.
     * </p>
     *
     * @return key used by this context; never null
     */
    @Override
    public Key key() {
        return key;
    }

    /**
     * Releases resources held by this context.
     *
     * <p>
     * This implementation holds no resources and performs no action. It is safe to
     * call multiple times.
     * </p>
     */
    @Override
    public void close() {
        // empty
    }

    /**
     * Generates a CMCE ciphertext and shared secret using the stored public key.
     *
     * @return result containing ciphertext and secret
     * @throws IllegalStateException if this context is not in encapsulate mode
     * @throws IOException           if encapsulation fails
     */
    @Override
    public KemResult encapsulate() throws IOException {
        if (!encapsulate) {
            throw new IllegalStateException("Not initialized for ENCAPSULATE");
        }
        try {
            final CMCEPublicKeyParameters keyParam = (CMCEPublicKeyParameters) PublicKeyFactory
                    .createKey(key.getEncoded());
            CMCEKEMGenerator gen = new CMCEKEMGenerator(new SecureRandom());
            SecretWithEncapsulation res = gen.generateEncapsulated(keyParam);
            byte[] secret = res.getSecret();
            byte[] ct = res.getEncapsulation();
            res.destroy();
            return new KemResult(ct, secret);
        } catch (DestroyFailedException e) {
            throw new IOException("CMCE encapsulate failed", e);
        }
    }

    /**
     * Extracts the shared secret from the given ciphertext using the stored private
     * key.
     *
     * @param ciphertext CMCE ciphertext (must be non-null and non-empty)
     * @return shared secret bytes
     * @throws IllegalStateException    if this context is not in decapsulate mode
     * @throws IllegalArgumentException if {@code ciphertext} is null or empty
     * @throws IOException              if decapsulation fails
     */
    @Override
    public byte[] decapsulate(byte[] ciphertext) throws IOException {
        if (encapsulate) {
            throw new IllegalStateException("Not initialized for DECAPSULATE");
        }
        try {
            final CMCEPrivateKeyParameters keyParam = (CMCEPrivateKeyParameters) PrivateKeyFactory
                    .createKey(key.getEncoded());
            CMCEKEMExtractor ex = new CMCEKEMExtractor(keyParam);
            return ex.extractSecret(ciphertext);
        } catch (Exception e) {
            throw new IOException("CMCE decapsulate failed", e);
        }
    }
}
