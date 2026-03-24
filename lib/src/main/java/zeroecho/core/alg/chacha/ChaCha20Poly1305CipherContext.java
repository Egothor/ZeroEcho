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
package zeroecho.core.alg.chacha;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;

/**
 * <h2>ChaCha20-Poly1305 cipher context (AEAD)</h2>
 *
 * Concrete {@link zeroecho.core.context.EncryptionContext} for the
 * {@code ChaCha20-Poly1305} AEAD construction. Configures a JCE
 * {@link javax.crypto.Cipher} with a 12-byte nonce (managed by the parent
 * {@link AbstractChaChaCipherContext}) and applies optional AAD obtained from
 * {@link ConfluxKeys#aad(String)} via the bound context.
 *
 * <h3>Behavior</h3>
 * <ul>
 * <li>Uses transformation {@code "ChaCha20-Poly1305"}.</li>
 * <li>Initializes with {@link javax.crypto.spec.IvParameterSpec} for the
 * 12-byte nonce.</li>
 * <li>Supplies Additional Authenticated Data (AAD) from the active context if
 * present.</li>
 * </ul>
 *
 * <h3>Usage</h3> <pre>{@code
 * CryptoAlgorithm alg = ...;
 * SecretKey key = ...; // ChaCha20 key (256-bit)
 * ChaCha20Poly1305Spec spec = ChaCha20Poly1305Spec.builder().header(null).build();
 *
 * // Encrypt
 * EncryptionContext enc = new ChaCha20Poly1305CipherContext(alg, key, true, spec, new SecureRandom());
 *
 * // Decrypt
 * EncryptionContext dec = new ChaCha20Poly1305CipherContext(alg, key, false, spec, new SecureRandom());
 * }</pre>
 *
 * @since 1.0
 */
final class ChaCha20Poly1305CipherContext extends AbstractChaChaCipherContext<ChaCha20Poly1305Spec> {
    /**
     * Creates a ChaCha20-Poly1305 context.
     *
     * @param alg  algorithm definition
     * @param key  ChaCha20 secret key
     * @param enc  {@code true} for encryption, {@code false} for decryption
     * @param spec algorithm-specific parameters
     * @param rnd  randomness source for nonce generation
     */
    protected ChaCha20Poly1305CipherContext(CryptoAlgorithm alg, SecretKey key, boolean enc, ChaCha20Poly1305Spec spec,
            java.security.SecureRandom rnd) {
        super(alg, key, enc, spec, rnd);
    }

    /**
     * Returns {@code "ChaCha20-Poly1305"} as the JCE transformation.
     *
     * @return transformation string
     */
    @Override
    protected String jceName() {
        return "ChaCha20-Poly1305";
    }

    /**
     * Initializes the cipher for the current mode with the supplied nonce and
     * optional AAD.
     *
     * <p>
     * Uses {@link javax.crypto.spec.IvParameterSpec} for the 12-byte nonce and, if
     * present, applies AAD retrieved from the bound context under
     * {@link ConfluxKeys#aad(String)}.
     * </p>
     *
     * @param cipher configured cipher instance
     * @param nonce  12-byte nonce value
     * @throws java.security.GeneralSecurityException if cipher initialization fails
     * @throws java.io.IOException                    if AAD retrieval/processing
     *                                                fails
     */
    @Override
    protected void initCipher(Cipher cipher, byte[] nonce) throws GeneralSecurityException, IOException {
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key, new IvParameterSpec(nonce));

        // AAD handling mirrors your AES-GCM path via ConfluxKeys.aad(id).
        //
        final String id = algorithm.id();
        byte[] aad = (context() == null) ? null : context().get(ConfluxKeys.aad(id));
        if (aad == null) {
            aad = new byte[0];
        }
        cipher.updateAAD(aad);
    }
}
