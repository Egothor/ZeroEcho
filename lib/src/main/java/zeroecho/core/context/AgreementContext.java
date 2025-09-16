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
package zeroecho.core.context;

import java.security.PublicKey;

/**
 * Context for performing key agreement protocols using a private key and a
 * peer's public key.
 *
 * <p>
 * An {@code AgreementContext} encapsulates the state needed to derive a shared
 * secret between two parties. It is created by a
 * {@link zeroecho.core.CryptoAlgorithm} for the
 * {@link zeroecho.core.KeyUsage#AGREEMENT} role. Typical implementations
 * include elliptic-curve Diffie–Hellman (ECDH) and X25519/X448.
 * </p>
 *
 * <h2>Lifecycle</h2>
 * <ul>
 * <li>Create a context via {@code CryptoAlgorithm#create(...)} or
 * {@code CryptoAlgorithms.create(...)} for the {@code AGREEMENT} role.</li>
 * <li>Call {@link #setPeerPublic(PublicKey)} with the peer’s public key.</li>
 * <li>Invoke {@link #deriveSecret()} once to compute the raw shared
 * secret.</li>
 * <li>Dispose of the context with {@link #close()} to release any internal
 * resources.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Shared secrets are returned as raw byte arrays; callers should
 * immediately feed them into a key-derivation function (KDF) and clear the
 * array when done.</li>
 * <li>Most agreements require validated public keys. Implementations should
 * enforce curve/mathematical constraints and reject invalid points.</li>
 * <li>Contexts are not generally thread-safe; do not share a single instance
 * across concurrent threads.</li>
 * </ul>
 *
 * @since 1.0
 */
public non-sealed interface AgreementContext extends CryptoContext {

    /**
     * Sets the peer's public key to be used in the key agreement.
     *
     * <p>
     * This method must be called before {@link #deriveSecret()}. Implementations
     * may validate that the provided key is suitable for the underlying algorithm
     * (e.g., curve membership checks).
     * </p>
     *
     * @param peer the peer's public key
     * @throws NullPointerException     if {@code peer} is {@code null}
     * @throws IllegalArgumentException if {@code peer} is not valid for this
     *                                  algorithm
     */
    void setPeerPublic(PublicKey peer);

    /**
     * Performs the key agreement and returns the derived raw shared secret.
     *
     * <p>
     * The returned byte array contains secret material and should be used
     * immediately in a KDF. Callers are responsible for clearing or zeroizing the
     * array after use to reduce the risk of leakage.
     * </p>
     *
     * @return a new byte array containing the raw shared secret
     * @throws IllegalStateException if the peer public key has not been set before
     *                               invocation
     */
    byte[] deriveSecret();
}
