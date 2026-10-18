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
package zeroecho.core.alg.chacha;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;

import conflux.CtxInterface;
import zeroecho.core.ConfluxKeys;
import zeroecho.core.CryptoAlgorithm;

/**
 * <h2>ChaCha20 cipher context (stream)</h2>
 *
 * Concrete {@link zeroecho.core.context.EncryptionContext} for the
 * {@code ChaCha20} stream cipher. Relies on the parent
 * {@link AbstractChaChaCipherContext} for streaming, nonce management, and
 * optional header handling, while configuring ChaCha20-specific parameters:
 * <ul>
 * <li>Transformation: {@code "ChaCha20"}.</li>
 * <li>12-byte nonce via {@link javax.crypto.spec.ChaCha20ParameterSpec}.</li>
 * <li>Initial counter sourced from {@link ChaChaSpec#initialCounter()},
 * optionally overridden via {@link ConfluxKeys#tagBits(String)} in the bound
 * context.</li>
 * </ul>
 *
 * <h3>Counter handling</h3> On attach, the counter is taken from the spec; if
 * the active context contains an integer under {@code ConfluxKeys.tagBits(id)},
 * that value overrides the spec and is used to initialize the cipher counter.
 * If absent, the spec's value is stored into the context for downstream
 * consumers.
 *
 * @since 1.0
 */
public final class ChaChaCipherContext extends AbstractChaChaCipherContext<ChaChaSpec> {
    /**
     * Creates a ChaCha20 context.
     *
     * @param alg  algorithm definition
     * @param key  ChaCha20 secret key
     * @param enc  {@code true} for encryption, {@code false} for decryption
     * @param spec ChaCha20 stream specification (includes initial counter)
     * @param rnd  randomness source for nonce generation
     */
    public ChaChaCipherContext(CryptoAlgorithm alg, SecretKey key, boolean enc, ChaChaSpec spec,
            java.security.SecureRandom rnd) {
        super(alg, key, enc, spec, rnd);
    }

    /**
     * Returns {@code "ChaCha20"} as the JCE transformation.
     *
     * @return transformation string
     */
    @Override
    protected String jceName() {
        return "ChaCha20";
    }

    /**
     * Initializes the cipher in the configured mode with the supplied nonce and
     * counter.
     *
     * <p>
     * Uses {@link javax.crypto.spec.ChaCha20ParameterSpec} with a 12-byte nonce and
     * an initial counter taken from {@link ChaChaSpec#initialCounter()} or, if
     * present, from {@link ConfluxKeys#tagBits(String)} in the bound context.
     * </p>
     *
     * @param cipher initialized cipher instance
     * @param nonce  12-byte nonce value
     * @throws java.security.GeneralSecurityException if cipher initialization fails
     * @throws java.io.IOException                    if context access or parameter
     *                                                resolution fails
     */
    @Override
    protected void initCipher(Cipher cipher, byte[] nonce) throws GeneralSecurityException, IOException {
        final String id = algorithm.id();
        int counter = spec.initialCounter();
        CtxInterface c = context();
        if (c != null) {
            Integer ctxCtr = c.get(ConfluxKeys.tagBits(id));
            if (ctxCtr != null) {
                counter = ctxCtr;
            } else {
                c.put(ConfluxKeys.tagBits(id), counter);
            }
        }
        cipher.init(encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, key,
                new ChaCha20ParameterSpec(nonce, counter));
    }
}
