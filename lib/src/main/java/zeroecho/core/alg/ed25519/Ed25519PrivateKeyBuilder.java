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

import zeroecho.core.alg.common.eddsa.AbstractEncodedPrivateKeyBuilder;

/**
 * <h2>Private key builder for Ed25519</h2>
 *
 * Concrete {@link zeroecho.core.spi.AsymmetricKeyBuilder} for importing and
 * wrapping Ed25519 private keys.
 *
 * <p>
 * This builder integrates with the JCA under the canonical key factory
 * algorithm name {@code "Ed25519"}. It consumes an
 * {@link Ed25519PrivateKeySpec}, which provides the encoded PKCS#8
 * representation of the private key.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Expose the JCA key factory name {@code "Ed25519"} for
 * interoperability.</li>
 * <li>Provide the encoded PKCS#8 bytes via
 * {@link Ed25519PrivateKeySpec#encoded()} for key material import.</li>
 * </ul>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Import a private key from its encoded PKCS#8 form
 * Ed25519PrivateKeySpec spec = new Ed25519PrivateKeySpec(pkcs8Bytes);
 * PrivateKey privateKey = CryptoAlgorithms.privateKey("Ed25519", spec);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances of this builder are stateless and may be
 * reused safely across threads.
 *
 * @since 1.0
 */
public final class Ed25519PrivateKeyBuilder extends AbstractEncodedPrivateKeyBuilder<Ed25519PrivateKeySpec> {
    /**
     * Returns the canonical JCA algorithm name for Ed25519 key factories.
     *
     * <p>
     * This value is used by the parent {@link AbstractEncodedPrivateKeyBuilder} to
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
     * Returns the PKCS#8 encoded bytes from the given key spec.
     *
     * <p>
     * This encoding is passed to the JCA {@code KeyFactory} for parsing into a
     * {@link java.security.PrivateKey} instance.
     * </p>
     *
     * @param spec the private key specification holding the PKCS#8 encoding
     * @return a defensive copy of the PKCS#8-encoded key bytes
     */
    @Override
    protected byte[] encodedPkcs8(final Ed25519PrivateKeySpec spec) {
        return spec.encoded();
    }
}
