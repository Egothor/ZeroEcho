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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import zeroecho.core.CryptoAlgorithm;
import zeroecho.core.spi.PublicKeyImporter;

/**
 * <h2>ECDSA Public Key Builder</h2>
 *
 * Implementation of {@link zeroecho.core.spi.PublicKeyImporter} for
 * {@link EcdsaPublicKeySpec}. This builder is responsible for importing ECDSA
 * public keys from X.509 SubjectPublicKeyInfo encodings.
 *
 * <p>
 * The exact supported operation is {@link #importPublic(EcdsaPublicKeySpec)}.
 * Generation and private import are registered through their own
 * operation-specific implementations.
 * </p>
 *
 * <h2>Encoding</h2> The {@link EcdsaPublicKeySpec} stores the public key in
 * standard X.509 DER format. This builder delegates to a JCA {@link KeyFactory}
 * for the {@code "EC"} algorithm to reconstruct a usable {@link PublicKey}.
 *
 * <h2>Usage</h2> Typically accessed through the session key-operation API or
 * {@link CryptoAlgorithm#publicKeyImporter(Class)}.
 *
 * <pre>{@code
 * // Example: Import an ECDSA public key
 * byte[] x509 = ...; // load SubjectPublicKeyInfo DER data
 * EcdsaPublicKeySpec spec = new EcdsaPublicKeySpec(x509);
 * PublicKey pub = new EcdsaPublicKeyBuilder().importPublic(spec);
 * }</pre>
 *
 * @since 1.0
 */
public final class EcdsaPublicKeyBuilder implements PublicKeyImporter<EcdsaPublicKeySpec> {

    /**
     * Imports a public key from an X.509 SubjectPublicKeyInfo specification.
     *
     * <p>
     * Uses a JCA {@link KeyFactory} instance for {@code "EC"} to parse the given
     * {@link EcdsaPublicKeySpec} and construct a {@link PublicKey}.
     * </p>
     *
     * @param spec public key specification containing X.509 DER encoding
     * @return reconstructed {@link PublicKey} instance
     * @throws GeneralSecurityException if the encoding is invalid or the key cannot
     *                                  be reconstructed
     */
    @Override
    public PublicKey importPublic(EcdsaPublicKeySpec spec) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("EC");
        return kf.generatePublic(new X509EncodedKeySpec(spec.encoded()));
    }
}
