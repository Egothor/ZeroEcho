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
package zeroecho.core.policy;

import java.security.Key;

import zeroecho.core.KeyUsage;
import zeroecho.core.spec.ContextSpec;

/**
 * A strategy interface for validating cryptographic keys, usages, and
 * specifications before contexts are created.
 *
 * <p>
 * A {@code CryptoPolicy} is consulted by higher layers (such as
 * {@link zeroecho.core.CryptoAlgorithms}) to enforce organizational or
 * security-specific rules. Policies may range from permissive (accept
 * everything) to strict (require minimum key sizes, algorithm whitelisting,
 * usage separation, etc.).
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li>Allow central enforcement of key strength and usage constraints.</li>
 * <li>Support extensibility without hardcoding checks into algorithms.</li>
 * <li>Enable application-specific security postures while sharing the same
 * underlying primitives.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * ZeroEchoSession session = new ZeroEchoSession()
 *         .withPolicy(CryptoPolicy.minStrength(128));
 *
 * // Later, when creating a context:
 * EncryptionContext ctx = session.createContext("AES", KeyUsage.ENCRYPT, secretKey);
 * }</pre>
 *
 * @param <S> context specification type
 * @param <K> key type
 * @since 1.0
 * @see zeroecho.sdk.ZeroEchoSession
 */
public interface CryptoPolicy<S extends ContextSpec, K extends Key> { // NOPMD
    /**
     * Validates an algorithm identifier, role, key, and spec.
     *
     * <p>
     * Implementations should throw an unchecked exception (typically
     * {@link IllegalArgumentException}) if the combination violates policy.
     * </p>
     *
     * @param id   canonical algorithm identifier
     * @param role intended key usage role
     * @param key  cryptographic key (may be {@code NullKey} for unkeyed flows)
     * @param spec optional context specification; may be {@code null}
     * @throws IllegalArgumentException if the parameters are not permitted by the
     *                                  policy
     */
    void validate(String id, KeyUsage role, K key, S spec);

    /**
     * Returns a permissive policy that accepts all keys, roles, and specs without
     * validation.
     *
     * <p>
     * This is the default when no explicit policy is configured.
     * </p>
     *
     * @param <S> context specification type
     * @param <K> key type
     * @return a permissive {@code CryptoPolicy}
     */
    static <S extends ContextSpec, K extends Key> CryptoPolicy<S, K> permissive() {
        return (id, role, key, spec) -> {
        };
    }

    /**
     * Returns a policy that enforces a minimum estimated key strength.
     *
     * <p>
     * Key strength is estimated in bits using
     * {@link SecurityStrengthAdvisor#estimateBits(String, Key)}. If the strength is
     * below {@code minBits}, validation fails with
     * {@link IllegalArgumentException}.
     * </p>
     *
     * @param minBits minimum acceptable estimated key strength, in bits
     * @param <S>     context specification type
     * @param <K>     key type
     * @return a {@code CryptoPolicy} that enforces minimum key strength
     * @throws IllegalArgumentException if {@code minBits} is negative
     */
    static <S extends ContextSpec, K extends Key> CryptoPolicy<S, K> minStrength(int minBits) {
        return (id, role, key, spec) -> {
            int est = SecurityStrengthAdvisor.estimateBits(id, key);
            if (est < minBits) {
                throw new IllegalArgumentException(
                        "Algorithm " + id + " key strength " + est + " bits is below minimum " + minBits + " bits");
            }
        };
    }
}
