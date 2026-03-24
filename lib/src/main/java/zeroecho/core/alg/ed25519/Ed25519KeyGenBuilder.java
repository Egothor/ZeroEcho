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
package zeroecho.core.alg.ed25519;

import zeroecho.core.alg.common.eddsa.AbstractEdDSAKeyGenBuilder;

/**
 * <h2>Key-pair builder for Ed25519</h2>
 *
 * Concrete {@link zeroecho.core.spi.AsymmetricKeyBuilder} implementation for
 * generating Ed25519 key pairs.
 *
 * <p>
 * This builder delegates to the JCA provider under the canonical algorithm name
 * {@code "Ed25519"}. It is registered by {@link Ed25519Algorithm} to support
 * key generation from an {@link Ed25519KeyGenSpec}.
 * </p>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Generate a new Ed25519 key pair with default parameters
 * Ed25519KeyGenSpec spec = Ed25519KeyGenSpec.defaultSpec();
 * KeyPair kp = CryptoAlgorithms.keyPair("Ed25519", spec);
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances of this builder are stateless and may be
 * reused safely across threads.
 *
 * @since 1.0
 */
public final class Ed25519KeyGenBuilder extends AbstractEdDSAKeyGenBuilder<Ed25519KeyGenSpec> {

    /**
     * Returns the canonical JCA algorithm name for Ed25519 key-pair generation.
     *
     * <p>
     * This method is invoked by the parent {@link AbstractEdDSAKeyGenBuilder} to
     * construct a {@code KeyPairGenerator}.
     * </p>
     *
     * @return the string {@code "Ed25519"}
     */
    @Override
    protected String jcaKeyPairAlg() {
        return "Ed25519";
    }
}
