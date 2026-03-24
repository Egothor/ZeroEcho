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
package zeroecho.core.alg.slhdsa;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * Builder for importing SLH-DSA private keys from encoded specifications.
 *
 * @since 1.0
 */
public final class SlhDsaPrivateKeyBuilder implements AsymmetricKeyBuilder<SlhDsaPrivateKeySpec> {

    private static final String ALG = "SLH-DSA";

    @Override
    public KeyPair generateKeyPair(SlhDsaPrivateKeySpec spec) {
        throw new UnsupportedOperationException("Generation not supported by this spec.");
    }

    @Override
    public PublicKey importPublic(SlhDsaPrivateKeySpec spec) {
        throw new UnsupportedOperationException("Use SlhDsaPublicKeySpec for public keys.");
    }

    @Override
    public PrivateKey importPrivate(SlhDsaPrivateKeySpec spec) throws GeneralSecurityException {
        KeyFactory kf = (spec.providerName() == null) ? KeyFactory.getInstance(ALG)
                : KeyFactory.getInstance(ALG, spec.providerName());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(spec.encoded()));
    }
}
