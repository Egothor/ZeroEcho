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
package zeroecho.core.alg.ed25519;

import zeroecho.core.alg.common.eddsa.AbstractEncodedPublicKeyBuilder;

/**
 * <h2>Public key builder for Ed25519</h2>
 *
 * Concrete {@link zeroecho.core.spi.AsymmetricKeyBuilder} for importing and
 * wrapping Ed25519 public keys.
 *
 * <p>
 * This builder integrates with the JCA under the canonical key factory
 * algorithm name {@code "Ed25519"}. It consumes an
 * {@link Ed25519PublicKeySpec}, which provides the encoded X.509 representation
 * of the public key.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Expose the JCA key factory name {@code "Ed25519"} for
 * interoperability.</li>
 * <li>Provide the encoded X.509 bytes via
 * {@link Ed25519PublicKeySpec#encoded()} for key material import.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Import a public key from its encoded X.509 form
 * Ed25519PublicKeySpec spec = new Ed25519PublicKeySpec(x509Bytes);
 * PublicKey publicKey = CryptoAlgorithms.publicKey("Ed25519", spec);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances of this builder are stateless and may be
 * reused safely across threads.
 *
 * @since 1.0
 */
public final class Ed25519PublicKeyBuilder extends AbstractEncodedPublicKeyBuilder<Ed25519PublicKeySpec> {
    /**
     * Returns the canonical JCA algorithm name for Ed25519 key factories.
     *
     * <p>
     * This value is used by the parent {@link AbstractEncodedPublicKeyBuilder} to
     * obtain a {@code KeyFactory}.
     * </p>
     *
     * @return the string {@code "Ed25519"}
     */
    @Override
    protected String jcaKeyFactoryAlg() {
        return "Ed25519";
    }

    /**
     * Returns the X.509 encoded bytes from the given key spec.
     *
     * <p>
     * This encoding is passed to the JCA {@code KeyFactory} for parsing into a
     * {@link java.security.PublicKey} instance.
     * </p>
     *
     * @param spec the public key specification holding the X.509 encoding
     * @return a defensive copy of the X.509-encoded key bytes
     */
    @Override
    protected byte[] encodedX509(final Ed25519PublicKeySpec spec) {
        return spec.encoded();
    }
}
