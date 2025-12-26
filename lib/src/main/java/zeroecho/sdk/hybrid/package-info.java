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
 * SDK-level hybrid cryptography utilities.
 *
 * <p>
 * This package groups hybrid composition helpers that combine classical and
 * post-quantum primitives at the SDK layer while keeping the underlying core
 * contracts unchanged. Hybrid constructions are exposed as regular streaming
 * contexts and builder integrations, so they can be used with existing pipeline
 * APIs (for example {@link zeroecho.sdk.builders.core.DataContentChainBuilder}
 * and trailer-oriented stages).
 * </p>
 *
 * <h2>Subpackages</h2>
 * <ul>
 * <li>{@link zeroecho.sdk.hybrid.kex} - hybrid key exchange (KEX) that composes
 * a classic agreement and a message-based (KEM-style) agreement into a single
 * derived shared secret, and emits an explicit peer message suitable for
 * transport.</li>
 * <li>{@link zeroecho.sdk.hybrid.derived} - derived-key utilities that consume
 * hybrid KEX output and inject purpose-separated keying material (key, optional
 * IV/nonce, optional AAD) into streaming builders while preserving fluent
 * builder usage.</li>
 * <li>{@link zeroecho.sdk.hybrid.signature} - hybrid signature composition that
 * combines two independent signature schemes and exposes them as a single
 * streaming {@link zeroecho.core.context.SignatureContext} suitable for
 * trailer-style pipeline stages.</li>
 * </ul>
 *
 * <h2>Design principles</h2>
 * <ul>
 * <li><b>Composition over modification</b>: hybrids are implemented as
 * SDK-level compositions over existing core contexts rather than by expanding
 * core API contracts.</li>
 * <li><b>Explicit messages where needed</b>: whenever a hybrid operation has
 * "to-be-sent" bytes (for example KEX peer messages), they are modeled as
 * explicit byte sequences rather than hidden side effects.</li>
 * <li><b>Key separation via KDF</b>: hybrid secrets are combined and expanded
 * using HKDF label separation and transcript binding; concatenation is avoided
 * as a primary combination method.</li>
 * </ul>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>Hybrid constructions increase protocol and implementation complexity.
 * Prefer clear profiles, stable transcript inputs, and explicit policy to avoid
 * ambiguous security expectations.</li>
 * <li>Do not log or otherwise expose sensitive material (private keys, seeds,
 * derived keying bytes, plaintexts, intermediate secrets).</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Hybrid contexts and builders are not thread-safe. Create a new instance per
 * independent operation and do not share instances across concurrent pipeline
 * executions.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.sdk.hybrid;
