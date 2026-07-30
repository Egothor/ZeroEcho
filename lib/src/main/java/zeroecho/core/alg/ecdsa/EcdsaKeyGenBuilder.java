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
package zeroecho.core.alg.ecdsa;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.spi.AsymmetricKeyPairGenerator;

/**
 * <h2>ECDSA Key Pair Generator</h2>
 *
 * Implementation of {@link zeroecho.core.spi.AsymmetricKeyPairGenerator} for
 * {@link EcdsaCurveSpec}. This builder is responsible for generating new
 * elliptic curve key pairs for use with the {@link EcdsaAlgorithm}.
 *
 * <p>
 * The exact supported operation is {@link #generateKeyPair(EcdsaCurveSpec)}.
 * Public and private import are registered separately through
 * {@link EcdsaPublicKeyBuilder} and {@link EcdsaPrivateKeyBuilder}.
 * </p>
 *
 * <h2>Usage</h2> Typically accessed through the session key-operation API or
 * {@link CryptoAlgorithm#asymmetricKeyPairGenerator(Class)}.
 *
 * <pre>{@code
 * // Example: Generate an ECDSA P-256 key pair
 * EcdsaCurveSpec spec = EcdsaCurveSpec.P256;
 * KeyPair kp = new EcdsaKeyGenBuilder().generateKeyPair(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class EcdsaKeyGenBuilder implements AsymmetricKeyPairGenerator<EcdsaCurveSpec> {
    /**
     * Generates a new elliptic curve key pair for the given curve specification.
     *
     * <p>
     * Internally uses the JCA {@link KeyPairGenerator} with the {@code "EC"}
     * algorithm and initializes it with an {@link ECGenParameterSpec} corresponding
     * to the curve name (e.g., {@code "secp256r1"}).
     * </p>
     *
     * @param spec the curve specification to use
     * @return newly generated EC {@link KeyPair}
     * @throws GeneralSecurityException if the curve is not supported by the
     *                                  provider
     */
    @Override
    public KeyPair generateKeyPair(EcdsaCurveSpec spec) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(spec.curveName()));
        return kpg.generateKeyPair();
    }
}
