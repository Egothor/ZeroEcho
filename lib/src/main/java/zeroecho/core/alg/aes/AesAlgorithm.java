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
package zeroecho.core.alg.aes;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import zeroecho.core.AlgorithmFamily;
import zeroecho.core.KeyUsage;
import zeroecho.core.alg.AbstractCryptoAlgorithm;
import zeroecho.core.context.EncryptionContext;
import zeroecho.core.spec.VoidSpec;
import zeroecho.core.spi.SymmetricKeyBuilder;

/**
 * AES algorithm registration and capability wiring.
 *
 * <p>
 * Registers streaming ENCRYPT/DECRYPT contexts for the {@code "AES"} family,
 * provides secure defaults (GCM/128), and exposes key builders for generation
 * and import.
 * </p>
 *
 * <ul>
 * <li>Capabilities:
 * <ul>
 * <li>ENCRYPT/DECRYPT → {@link AesCipherContext} with {@link AesSpec}</li>
 * <li>VoidSpec fallback → {@code AesSpec.gcm128(null)}</li>
 * </ul>
 * </li>
 * <li>Key builders:
 * <ul>
 * <li>{@link AesKeyGenSpec} → JCA {@link javax.crypto.KeyGenerator}</li>
 * <li>{@link AesKeyImportSpec} → {@link javax.crypto.spec.SecretKeySpec}</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <h2>Thread‑safety</h2> Registration is static and thread‑safe. Produced
 * contexts are stateful and not thread‑safe.
 *
 * @since 1.0
 */
public final class AesAlgorithm extends AbstractCryptoAlgorithm {
    /**
     * Constructs the AES algorithm descriptor and performs capability registration.
     */
    public AesAlgorithm() {
        super("AES", "AES (CBC/GCM/CTR)");

        // Context capabilities
        capability(AlgorithmFamily.SYMMETRIC, KeyUsage.ENCRYPT, EncryptionContext.class, SecretKey.class, AesSpec.class,
                (SecretKey k, AesSpec s) -> new AesCipherContext(this, k, true, s, new SecureRandom()),
                () -> AesSpec.gcm128(null));

        capability(AlgorithmFamily.SYMMETRIC, KeyUsage.DECRYPT, EncryptionContext.class, SecretKey.class, AesSpec.class,
                (SecretKey k, AesSpec s) -> new AesCipherContext(this, k, false, s, new SecureRandom()),
                () -> AesSpec.gcm128(null));

        capability(AlgorithmFamily.SYMMETRIC, KeyUsage.ENCRYPT, EncryptionContext.class, SecretKey.class,
                VoidSpec.class, (SecretKey k, VoidSpec s) -> new AesCipherContext(this, k, true, AesSpec.gcm128(null),
                        new SecureRandom()),
                () -> VoidSpec.INSTANCE);

        capability(AlgorithmFamily.SYMMETRIC, KeyUsage.DECRYPT, EncryptionContext.class, SecretKey.class,
                VoidSpec.class, (SecretKey k, VoidSpec s) -> new AesCipherContext(this, k, false, AesSpec.gcm128(null),
                        new SecureRandom()),
                () -> VoidSpec.INSTANCE);

        // Secret generation builder (AesKeyGenSpec)
        registerSymmetricKeyBuilder(AesKeyGenSpec.class, new SymmetricKeyBuilder<>() {
            @Override
            public SecretKey generateSecret(AesKeyGenSpec spec) throws GeneralSecurityException {
                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(spec.keySizeBits(), new SecureRandom());
                return kg.generateKey();
            }

            @Override
            public SecretKey importSecret(AesKeyGenSpec spec) {
                throw new UnsupportedOperationException("Use AesKeyImportSpec for importing AES keys");
            }
        }, AesKeyGenSpec::aes256);

        // Secret import builder (AesKeyImportSpec)
        registerSymmetricKeyBuilder(AesKeyImportSpec.class, new SymmetricKeyBuilder<>() {
            @Override
            public SecretKey generateSecret(AesKeyImportSpec spec) {
                throw new UnsupportedOperationException("Use AesKeyGenSpec to generate AES keys");
            }

            @Override
            public SecretKey importSecret(AesKeyImportSpec spec) {
                return new SecretKeySpec(spec.key(), "AES");
            }
        }, null);
    }
}
