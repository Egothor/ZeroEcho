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
package zeroecho.core.alg.ed448;

import zeroecho.core.alg.common.eddsa.AbstractEdDSAKeyGenBuilder;

/**
 * <h2>Ed448 Key-Pair Builder</h2>
 *
 * Concrete key generation builder for the Ed448 Edwards-curve Digital Signature
 * Algorithm, standardized in
 * <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>.
 *
 * <p>
 * This builder integrates with the JCA {@link java.security.KeyPairGenerator}
 * under the canonical algorithm name {@code "Ed448"}. It is responsible for
 * producing fresh {@link java.security.KeyPair} instances; key import is
 * delegated to {@link Ed448PublicKeyBuilder} and
 * {@link Ed448PrivateKeyBuilder}.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Generate a new Ed448 key pair
 * Ed448KeyGenBuilder builder = new Ed448KeyGenBuilder();
 * KeyPair kp = builder.generateKeyPair(Ed448KeyGenSpec.defaultSpec());
 * }</pre>
 *
 * <h2>Thread-safety</h2> Instances are stateless and may be reused across
 * threads. Each call creates a new {@link java.security.KeyPairGenerator}.
 *
 * @since 1.0
 */
public final class Ed448KeyGenBuilder extends AbstractEdDSAKeyGenBuilder<Ed448KeyGenSpec> {
    /**
     * Returns the canonical JCA algorithm identifier for Ed448 key pair generation.
     *
     * @return the string {@code "Ed448"}
     */
    @Override
    protected String jcaKeyPairAlg() {
        return "Ed448";
    }
}
