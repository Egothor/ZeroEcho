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
 * Specifications for keys and per-operation parameters.
 *
 * <p>
 * This package defines lightweight, strongly typed specifications used when
 * creating cryptographic contexts. Key specifications describe how a key should
 * be generated or imported for a particular family, while context
 * specifications supply optional, per-operation parameters (for example,
 * padding or nonce strategy). Algorithms that need no extra parameters use a
 * singleton placeholder.
 * </p>
 *
 * <h2>Key elements</h2>
 * <ul>
 * <li>{@link AlgorithmKeySpec} - marker interface for algorithm-specific key
 * specs used by key builders.</li>
 * <li>{@link ContextSpec} - marker interface for per-operation parameters
 * supplied to context creation.</li>
 * <li>{@link VoidSpec} - singleton context spec used when an algorithm requires
 * no additional parameters.</li>
 * </ul>
 *
 * <h2>Typical usage</h2> <pre>{@code
 * // Algorithm requires no per-operation parameters.
 * zeroecho.core.context.CryptoContext ctx =
 *     algo.create(zeroecho.core.KeyUsage.SIGN, privateKey, zeroecho.core.spec.VoidSpec.INSTANCE);
 *
 * // Algorithm with parameters: pass an algorithm-specific ContextSpec implementation.
 * // Example: RSA with OAEP/PSS, AEAD tag length, etc.
 * // zeroecho.core.context.CryptoContext ctx =
 * //     algo.create(zeroecho.core.KeyUsage.ENCRYPT, key, someAlgorithmSpecificSpec);
 * }</pre>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Specification types should be immutable and safe to share across
 * operations.</li>
 * <li>Key specifications and context specifications keep configuration separate
 * from runtime state, improving clarity and reuse.</li>
 * <li>Callers should prefer library-provided spec classes and avoid
 * implementing the marker interfaces directly unless extending the library with
 * new families.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.spec;
