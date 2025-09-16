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
package zeroecho.core.alg.ed448;

import zeroecho.core.alg.common.eddsa.AbstractEncodedPublicKeyBuilder;
import zeroecho.core.spec.AlgorithmKeySpec;
import zeroecho.core.spi.AsymmetricKeyBuilder;

/**
 * <h2>Ed448 Public Key Builder</h2>
 *
 * Concrete builder for importing Ed448 public keys from their X.509-encoded
 * representation.
 *
 * <p>
 * This class extends {@link AbstractEncodedPublicKeyBuilder} and specifies the
 * Ed448 algorithm. It reconstructs {@link java.security.PublicKey} instances
 * from {@link Ed448PublicKeySpec}, which carries the raw encoded form.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Provide the canonical JCA key factory algorithm name
 * ({@code "Ed448"}).</li>
 * <li>Extract the X.509-encoded key bytes from {@link Ed448PublicKeySpec}.</li>
 * <li>Delegate actual key reconstruction to
 * {@link java.security.KeyFactory}.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Import an Ed448 public key from encoded bytes
 * Ed448PublicKeySpec spec = new Ed448PublicKeySpec(x509Bytes);
 * PublicKey key = new Ed448PublicKeyBuilder().importPublic(spec);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Stateless and safe for concurrent use. Each call to
 * {@link AsymmetricKeyBuilder#importPublic(AlgorithmKeySpec)
 * importPublic(Ed448PublicKeySpec)} creates a new
 * {@link java.security.KeyFactory}.
 *
 * @since 1.0
 */
public final class Ed448PublicKeyBuilder extends AbstractEncodedPublicKeyBuilder<Ed448PublicKeySpec> {
    /**
     * Returns the canonical JCA key factory algorithm name for Ed448.
     *
     * @return the string {@code "Ed448"}
     */
    @Override
    protected String jcaKeyFactoryAlg() {
        return "Ed448";
    }

    /**
     * Returns the X.509-encoded public key bytes from the given specification.
     *
     * @param spec the {@link Ed448PublicKeySpec} holding encoded public key data
     * @return raw X.509-encoded public key bytes
     */
    @Override
    protected byte[] encodedX509(Ed448PublicKeySpec spec) {
        return spec.encoded();
    }
}
