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

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Ed448 Key Generation Specification</h2>
 *
 * Marker specification for generating Ed448 key pairs.
 *
 * <p>
 * Unlike parameterized algorithms (e.g., RSA with modulus size), Ed448 has
 * fixed domain parameters defined in
 * <a href="https://www.rfc-editor.org/rfc/rfc8032">RFC 8032</a>. As a result,
 * this spec carries no configuration fields - it serves only as a typed handle
 * linking {@link Ed448KeyGenBuilder} with the surrounding framework.
 * </p>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Generate a new Ed448 key pair using the default spec
 * KeyPair kp = new Ed448KeyGenBuilder().generateKeyPair(Ed448KeyGenSpec.defaultSpec());
 * }</pre>
 *
 * <h2>Thread-safety</h2> The {@link #defaultSpec()} instance is immutable and
 * safe to reuse across threads.
 *
 * @since 1.0
 */
public final class Ed448KeyGenSpec implements AlgorithmKeySpec {
    private static final Ed448KeyGenSpec DEFAULT = new Ed448KeyGenSpec();

    /**
     * Returns the shared default specification instance for Ed448 key generation.
     *
     * <p>
     * Since Ed448 has no configurable generation parameters, all key generation
     * uses this singleton. This avoids unnecessary object allocation and clarifies
     * intent.
     * </p>
     *
     * @return the singleton {@code Ed448KeyGenSpec} instance
     */
    public static Ed448KeyGenSpec defaultSpec() {
        return DEFAULT;
    }
}
