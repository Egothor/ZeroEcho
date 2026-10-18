/* *****************************************************************************
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
 * Derived-key utilities for integrating hybrid KEX output with streaming
 * builders.
 *
 * <p>
 * This package provides a thin, SDK-level integration layer between hybrid key
 * exchange ({@link zeroecho.sdk.hybrid.kex.HybridKexContext} /
 * {@link zeroecho.sdk.hybrid.kex.HybridKexExporter}) and streaming data-content
 * builders (for example AES/ChaCha/HMAC builders in
 * {@link zeroecho.sdk.builders.alg}).
 * </p>
 *
 * <p>
 * The central concept is <b>derived material</b>: purpose-separated keying
 * bytes (key, optional IV/nonce, optional AAD) derived via HKDF labels. The
 * material is then applied to an existing builder via {@code applyTo(...)}
 * which returns the same builder instance to preserve fluent pipeline
 * construction.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li>Keep cryptographic primitives unchanged; only inject derived
 * parameters.</li>
 * <li>Provide safe-by-construction key separation using labels and transcript
 * binding.</li>
 * <li>Preserve fluent builder usage by returning the original builder from
 * {@code applyTo(...)}.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.sdk.hybrid.derived;
