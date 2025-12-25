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
package zeroecho.core.alg.mldsa;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * Builder for importing ML-DSA private keys from encoded specifications.
 *
 * @since 1.0
 */
public final class MldsaPrivateKeyBuilder implements AsymmetricKeyBuilder<MldsaPrivateKeySpec> {

    private static final String ALG = "ML-DSA";

    /**
     * Generation is not supported by this spec.
     *
     * @param spec encoded private key spec
     * @return never returns normally
     * @throws UnsupportedOperationException always
     */
    @Override
    public KeyPair generateKeyPair(MldsaPrivateKeySpec spec) {
        throw new UnsupportedOperationException("Generation not supported by this spec.");
    }

    /**
     * Public key import is not supported by this spec.
     *
     * @param spec encoded private key spec
     * @return never returns normally
     * @throws UnsupportedOperationException always
     */
    @Override
    public PublicKey importPublic(MldsaPrivateKeySpec spec) {
        throw new UnsupportedOperationException("Use MldsaPublicKeySpec for public keys.");
    }

    /**
     * Imports a private key from PKCS#8 encoding.
     *
     * @param spec encoded private key spec
     * @return imported private key
     * @throws GeneralSecurityException if the key cannot be parsed or the provider
     *                                  does not support ML-DSA
     */
    @Override
    public PrivateKey importPrivate(MldsaPrivateKeySpec spec) throws GeneralSecurityException {
        KeyFactory kf = (spec.providerName() == null) ? KeyFactory.getInstance(ALG)
                : KeyFactory.getInstance(ALG, spec.providerName());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(spec.encoded()));
    }
}
