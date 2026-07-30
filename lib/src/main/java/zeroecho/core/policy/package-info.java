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
/**
 * Policy enforcement for algorithms, keys, and specifications.
 *
 * <p>
 * This package centralizes checks that validate algorithm identifiers, intended
 * roles, keys, and optional specifications before a context is created.
 * Policies allow an application to enforce organizational rules without
 * hard-wiring constraints into individual algorithms.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link CryptoPolicy} - strategy interface consulted during context
 * creation to validate the combination of algorithm id,
 * {@link zeroecho.core.KeyUsage} role, key, and optional spec.</li>
 * <li>{@link SecurityStrengthAdvisor} - utility that estimates a conservative
 * security strength in bits from an algorithm family id and a key, used by
 * policies such as minimum-strength guards.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * zeroecho.sdk.ZeroEchoSession session = new zeroecho.sdk.ZeroEchoSession()
 *     .withPolicy(zeroecho.core.policy.CryptoPolicy.minStrength(128));
 *
 * // The session applies the policy without changing other consumers.
 * zeroecho.core.context.EncryptionContext ctx =
 *     session.createContext("AES", zeroecho.core.KeyUsage.ENCRYPT, secretKey);
 * }</pre>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Policies can be permissive or strict, ranging from "accept all" to
 * enforcing whitelists and minimum key strengths.</li>
 * <li>Strength estimation favors safe lower bounds and relies on visible key
 * characteristics (for example, modulus bits for RSA, key length for AES, or
 * NIST-level hints for KEMs).</li>
 * <li>Validation failures are signaled using unchecked exceptions suitable for
 * configuration-time errors.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.policy;
