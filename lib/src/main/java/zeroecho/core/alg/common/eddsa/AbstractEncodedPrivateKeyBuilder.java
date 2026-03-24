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
package zeroecho.core.alg.common.eddsa;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * <h2>Abstract EdDSA Encoded Private Key Builder</h2>
 *
 * Base class for reconstructing EdDSA private keys (e.g., Ed25519, Ed448) from
 * PKCS#8-encoded specifications.
 *
 * <p>
 * Unlike {@link AbstractEdDSAKeyGenBuilder}, which is responsible for
 * generating fresh key pairs, this class focuses on <b>importing existing
 * private keys</b> from their encoded representation. Public key import and key
 * pair generation are deliberately unsupported here.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Define {@link #jcaKeyFactoryAlg()} to specify the canonical JCA algorithm
 * name (e.g., {@code "Ed25519"} or {@code "Ed448"}).</li>
 * <li>Define {@link #encodedPkcs8(AlgorithmKeySpec)} to extract the raw
 * PKCS#8-encoded private key material from the given spec.</li>
 * <li>Provide an {@link #importPrivate(AlgorithmKeySpec)} implementation that
 * rebuilds a {@link PrivateKey} using {@link KeyFactory} and the PKCS#8-encoded
 * material.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2> Stateless and safe for concurrent use. Each import
 * operation creates a new {@link KeyFactory} instance internally.
 *
 * @param <S> the algorithm-specific key specification carrying PKCS#8 data
 *
 * @since 1.0
 */
public abstract class AbstractEncodedPrivateKeyBuilder<S extends AlgorithmKeySpec> implements AsymmetricKeyBuilder<S> {
    /**
     * Returns the canonical JCA algorithm identifier used by
     * {@link KeyFactory#getInstance(String)}.
     *
     * <p>
     * Must be one of the algorithm names recognized by the JDK (e.g.,
     * {@code "Ed25519"}, {@code "Ed448"}).
     * </p>
     *
     * @return the JCA algorithm identifier string
     */
    protected abstract String jcaKeyFactoryAlg(); // e.g., "Ed25519", "Ed448"

    /**
     * Extracts the raw PKCS#8-encoded private key bytes from the given spec.
     *
     * <p>
     * Subclasses must implement this to pull the encoded material from their
     * {@link AlgorithmKeySpec} representation.
     * </p>
     *
     * @param spec algorithm-specific key specification
     * @return PKCS#8-encoded private key bytes
     */
    protected abstract byte[] encodedPkcs8(S spec);

    /**
     * Unsupported in this builder, since generation is handled by the
     * {@link AbstractEdDSAKeyGenBuilder}.
     *
     * @param spec algorithm-specific key specification
     * @return never returns normally
     * @throws UnsupportedOperationException always thrown
     */
    @Override
    public KeyPair generateKeyPair(S spec) {
        throw new UnsupportedOperationException("Generation not supported by this spec.");
    }

    /**
     * Unsupported in this builder, since public key import is delegated to the
     * matching {@code *PublicKeySpec} builder.
     *
     * @param spec algorithm-specific key specification
     * @return never returns normally
     * @throws UnsupportedOperationException always thrown
     */
    @Override
    public PublicKey importPublic(S spec) {
        throw new UnsupportedOperationException("Use the corresponding PublicKeySpec.");
    }

    /**
     * Imports an EdDSA private key from its PKCS#8-encoded form.
     *
     * <p>
     * This method uses {@link KeyFactory} initialized with the algorithm returned
     * by {@link #jcaKeyFactoryAlg()} to parse the bytes provided by
     * {@link #encodedPkcs8(AlgorithmKeySpec)}.
     * </p>
     *
     * @param spec algorithm-specific key specification containing PKCS#8 bytes
     * @return a reconstructed {@link PrivateKey} instance
     * @throws GeneralSecurityException if the key material is invalid or the JCA
     *                                  provider does not support the algorithm
     */
    @Override
    public PrivateKey importPrivate(S spec) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance(jcaKeyFactoryAlg());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encodedPkcs8(spec)));
    }
}
