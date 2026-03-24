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

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.spi.SymmetricKeyBuilder;

/**
 * <h2>Abstract base for ChaCha family algorithms</h2>
 *
 * Provides common registration logic for ChaCha20-based algorithms within the
 * ZeroEcho framework. Extends {@link zeroecho.core.alg.AbstractCryptoAlgorithm}
 * and installs symmetric key builders for both key generation and key import.
 *
 * <h3>Registered key builders</h3>
 * <ul>
 * <li>{@link zeroecho.core.alg.chacha.ChaChaKeyGenSpec} - generates new random
 * ChaCha keys of configurable size (default 256-bit).</li>
 * <li>{@link zeroecho.core.alg.chacha.ChaChaKeyImportSpec} - imports externally
 * supplied ChaCha keys as {@link javax.crypto.SecretKey} instances.</li>
 * </ul>
 *
 * <h3>Notes</h3>
 * <ul>
 * <li>Generation uses {@link javax.crypto.KeyGenerator} with algorithm
 * {@code "ChaCha20"}.</li>
 * <li>Import wraps the raw key material with
 * {@link javax.crypto.spec.SecretKeySpec}.</li>
 * <li>Attempts to generate a key via {@code ChaChaKeyImportSpec} or import via
 * {@code ChaChaKeyGenSpec} will throw
 * {@link UnsupportedOperationException}.</li>
 * </ul>
 *
 * <h3>Example</h3> <pre>{@code
 * AbstractChaChaAlgorithm algo = ...;
 *
 * // Generate a fresh 256-bit key
 * SecretKey key = algo.generateSecret(ChaChaKeyGenSpec.chacha256());
 *
 * // Import an existing key
 * SecretKey imported = algo.importSecret(new ChaChaKeyImportSpec(rawBytes));
 * }</pre>
 *
 * @since 1.0
 */
abstract class AbstractChaChaAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Constructs a ChaCha-based algorithm definition and registers symmetric key
     * builders for generation and import.
     *
     * @param id    canonical algorithm identifier (e.g., "ChaCha20/Poly1305")
     * @param title human-readable name for diagnostics
     */
    protected AbstractChaChaAlgorithm(String id, String title) {
        super(id, title);

        // register once for both algorithms (same 256-bit key)
        registerSymmetricKeyBuilder(ChaChaKeyGenSpec.class, new SymmetricKeyBuilder<>() {
            @Override
            public SecretKey generateSecret(ChaChaKeyGenSpec spec) throws GeneralSecurityException {
                KeyGenerator kg = KeyGenerator.getInstance("ChaCha20");
                kg.init(spec.keySizeBits(), new SecureRandom());
                return kg.generateKey();
            }

            @Override
            public SecretKey importSecret(ChaChaKeyGenSpec spec) {
                throw new UnsupportedOperationException("Use ChaChaKeyImportSpec for importing ChaCha keys");
            }
        }, ChaChaKeyGenSpec::chacha256);

        registerSymmetricKeyBuilder(ChaChaKeyImportSpec.class, new SymmetricKeyBuilder<>() {
            @Override
            public SecretKey generateSecret(ChaChaKeyImportSpec spec) {
                throw new UnsupportedOperationException("Use ChaChaKeyGenSpec to generate ChaCha keys");
            }

            @Override
            public SecretKey importSecret(ChaChaKeyImportSpec spec) {
                return new SecretKeySpec(spec.key(), "ChaCha20");
            }
        }, null);
    }
}
