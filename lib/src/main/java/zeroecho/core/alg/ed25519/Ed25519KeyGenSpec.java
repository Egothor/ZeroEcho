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

import zeroecho.core.spec.AlgorithmKeySpec;

/**
 * <h2>Specification for Ed25519 key-pair generation</h2>
 *
 * Marker {@link zeroecho.core.spec.AlgorithmKeySpec} used to request generation
 * of Ed25519 key pairs.
 *
 * <p>
 * Ed25519 has no tunable domain parameters (e.g., key size or curve options).
 * Therefore, this spec acts as a simple token to identify the algorithm when
 * invoking key generation. All instances are equivalent; applications should
 * typically use {@link #defaultSpec()}.
 * </p>
 *
 * <h2>Usage example</h2> <pre>{@code
 * // Generate a new Ed25519 key pair using the default spec
 * KeyPair kp = session.keyBuilders().asymmetric()
 *     .generateKeyPair("Ed25519", Ed25519KeyGenSpec.defaultSpec());
 * }</pre>
 *
 * <h2>Thread-safety</h2> The default spec instance is immutable and safe to
 * reuse across threads.
 *
 * @since 1.0
 */
public final class Ed25519KeyGenSpec implements AlgorithmKeySpec {
    private static final Ed25519KeyGenSpec DEFAULT = new Ed25519KeyGenSpec();

    /**
     * Returns the canonical, shared default spec instance for Ed25519 key
     * generation.
     *
     * <p>
     * Since Ed25519 has no configurable parameters, this singleton should be used
     * for all generation requests. Applications may still construct additional
     * instances, but they are functionally identical.
     * </p>
     *
     * @return the default Ed25519 key generation spec
     */
    public static Ed25519KeyGenSpec defaultSpec() {
        return DEFAULT;
    }
}
