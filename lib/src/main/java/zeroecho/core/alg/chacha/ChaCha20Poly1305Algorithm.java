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

import zeroecho.core.SymmetricHeaderCodec;

/**
 * <h2>ChaCha20-Poly1305 (AEAD) algorithm</h2>
 *
 * Registers the {@code ChaCha20-Poly1305} AEAD cipher within the ZeroEcho
 * framework. Extends {@link AbstractChaChaAlgorithm} and declares symmetric
 * capabilities for encryption and decryption using either
 * {@link ChaCha20Poly1305Spec} or {@link zeroecho.core.spec.VoidSpec}
 * (convenience default mirroring AES-GCM).
 *
 * <h3>Capabilities</h3>
 * <ul>
 * <li><b>Encrypt</b>:
 * <ul>
 * <li>Family: {@link zeroecho.core.AlgorithmFamily#SYMMETRIC}</li>
 * <li>Usage: {@link zeroecho.core.KeyUsage#ENCRYPT}</li>
 * <li>Context: {@link zeroecho.core.context.EncryptionContext}</li>
 * <li>Key: {@link javax.crypto.SecretKey}</li>
 * <li>Spec: {@link ChaCha20Poly1305Spec} (or
 * {@link zeroecho.core.spec.VoidSpec} default)</li>
 * </ul>
 * </li>
 * <li><b>Decrypt</b>:
 * <ul>
 * <li>Family: {@link zeroecho.core.AlgorithmFamily#SYMMETRIC}</li>
 * <li>Usage: {@link zeroecho.core.KeyUsage#DECRYPT}</li>
 * <li>Context: {@link zeroecho.core.context.EncryptionContext}</li>
 * <li>Key: {@link javax.crypto.SecretKey}</li>
 * <li>Spec: {@link ChaCha20Poly1305Spec} (or
 * {@link zeroecho.core.spec.VoidSpec} default)</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h3>Defaults</h3> When used with {@link zeroecho.core.spec.VoidSpec}, a
 * minimal {@link ChaCha20Poly1305Spec} is synthesized with no
 * {@link SymmetricHeaderCodec} header. Nonces are 12 bytes and managed by the
 * corresponding cipher context.
 *
 * <h3>Example</h3> <pre>{@code
 * var algo = new ChaCha20Poly1305Algorithm();
 * SecretKey key = algo.generateSecret(ChaChaKeyGenSpec.chacha256());
 *
 * // Encrypt with explicit spec
 * var spec = ChaCha20Poly1305Spec.builder().header(null).build();
 * EncryptionContext enc = algo.newContext(
 *     zeroecho.core.AlgorithmFamily.SYMMETRIC,
 *     zeroecho.core.KeyUsage.ENCRYPT, key, spec);
 *
 * // Decrypt using VoidSpec default
 * EncryptionContext dec = algo.newContext(
 *     zeroecho.core.AlgorithmFamily.SYMMETRIC,
 *     zeroecho.core.KeyUsage.DECRYPT, key, zeroecho.core.spec.VoidSpec.INSTANCE);
 * }</pre>
 *
 * @since 1.0
 */
public final class ChaCha20Poly1305Algorithm extends AbstractChaChaAlgorithm {
    /**
     * Creates and registers the ChaCha20-Poly1305 AEAD algorithm with
     * encryption/decryption capabilities for {@link ChaCha20Poly1305Spec} and
     * {@link zeroecho.core.spec.VoidSpec} defaults.
     */
    public ChaCha20Poly1305Algorithm() {
        super("CHACHA20-POLY1305", "ChaCha20-Poly1305 (AEAD)");
        capability(zeroecho.core.AlgorithmFamily.SYMMETRIC, zeroecho.core.KeyUsage.ENCRYPT,
                zeroecho.core.context.EncryptionContext.class, javax.crypto.SecretKey.class, ChaCha20Poly1305Spec.class,
                (k, s) -> new ChaCha20Poly1305CipherContext(this, k, true, s, new java.security.SecureRandom()),
                () -> ChaCha20Poly1305Spec.builder().header(null).build());

        capability(zeroecho.core.AlgorithmFamily.SYMMETRIC, zeroecho.core.KeyUsage.DECRYPT,
                zeroecho.core.context.EncryptionContext.class, javax.crypto.SecretKey.class, ChaCha20Poly1305Spec.class,
                (k, s) -> new ChaCha20Poly1305CipherContext(this, k, false, s, new java.security.SecureRandom()),
                () -> ChaCha20Poly1305Spec.builder().header(null).build());

        // VoidSpec defaults like AES-GCM
        capability(zeroecho.core.AlgorithmFamily.SYMMETRIC, zeroecho.core.KeyUsage.ENCRYPT,
                zeroecho.core.context.EncryptionContext.class, javax.crypto.SecretKey.class,
                zeroecho.core.spec.VoidSpec.class,
                (k, v) -> new ChaCha20Poly1305CipherContext(this, k, true,
                        ChaCha20Poly1305Spec.builder().header(null).build(), new java.security.SecureRandom()),
                () -> zeroecho.core.spec.VoidSpec.INSTANCE);

        capability(zeroecho.core.AlgorithmFamily.SYMMETRIC, zeroecho.core.KeyUsage.DECRYPT,
                zeroecho.core.context.EncryptionContext.class, javax.crypto.SecretKey.class,
                zeroecho.core.spec.VoidSpec.class,
                (k, v) -> new ChaCha20Poly1305CipherContext(this, k, false,
                        ChaCha20Poly1305Spec.builder().header(null).build(), new java.security.SecureRandom()),
                () -> zeroecho.core.spec.VoidSpec.INSTANCE);
    }
}
