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
/**
 * Concrete cryptographic algorithms and small helpers used by algorithms.
 *
 * <p>
 * This package hosts provider-specific and library-native implementations of
 * algorithms along with lightweight utilities that assist those
 * implementations. It focuses on binding algorithm roles to runtime contexts,
 * publishing capabilities for discovery, and keeping construction logic concise
 * and safe.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Provide concrete algorithm classes that can be discovered and registered
 * by {@link zeroecho.core.CryptoAlgorithms}.</li>
 * <li>Offer a convenience base class {@link AbstractCryptoAlgorithm} to
 * standardize capability declaration and runtime factory binding.</li>
 * <li>Publish structured metadata (capabilities) for higher layers to inspect
 * and select suitable algorithms.</li>
 * </ul>
 *
 * <h2>Key concepts</h2>
 * <ul>
 * <li><b>Algorithm model:</b> Implementations conform to
 * {@link zeroecho.core.CryptoAlgorithm}, exposing canonical identifiers,
 * provider names, priorities, and role bindings.</li>
 * <li><b>Roles and contexts:</b> Roles are enumerated by
 * {@link zeroecho.core.KeyUsage} and map to concrete runtime contexts that
 * implement {@link zeroecho.core.context.CryptoContext}.</li>
 * <li><b>Capabilities:</b> Each declared role produces a
 * {@link zeroecho.core.Capability} descriptor describing family
 * ({@link zeroecho.core.AlgorithmFamily}), role, context type, accepted key
 * type, and optional specification type.</li>
 * </ul>
 *
 * <h2>Capability binding</h2>
 * <p>
 * Implementations typically extend {@link AbstractCryptoAlgorithm} and use its
 * {@code capability(...)} method to perform two actions atomically:
 * </p>
 * <ul>
 * <li><b>Runtime binding:</b> register a factory that constructs the role
 * specific context from a key and optional
 * {@link zeroecho.core.spec.ContextSpec}.</li>
 * <li><b>Metadata publication:</b> add a {@link zeroecho.core.Capability} to
 * the algorithm so that higher layers can discover supported features.</li>
 * </ul>
 *
 * <h2>Construction and safety</h2>
 * <ul>
 * <li>Algorithm instances are expected to be immutable and safe to share across
 * threads once constructed.</li>
 * <li>Factories must return a context assignable to the declared context type;
 * a mismatch is a programming error and should result in a failure during
 * creation.</li>
 * <li>Null checks and basic type validation are performed eagerly to fail fast
 * on misconfiguration.</li>
 * </ul>
 *
 * <h2>Extensibility</h2>
 * <ul>
 * <li>New algorithms should prefer extending {@link AbstractCryptoAlgorithm} to
 * reduce boilerplate and keep capability descriptions consistent.</li>
 * <li>Additional roles can be introduced by declaring further capability
 * bindings that share the same canonical algorithm id.</li>
 * <li>Provider specific implementations should keep provider details
 * encapsulated behind context factories.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg;
