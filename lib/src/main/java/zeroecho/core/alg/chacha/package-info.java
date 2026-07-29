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
 * ChaCha algorithm implementation and runtime wiring.
 *
 * <p>
 * This package provides the ChaCha capability set for the core layer, including
 * the stream cipher ChaCha20 and the AEAD construction ChaCha20-Poly1305. The
 * module contains algorithm descriptors, streaming cipher contexts,
 * configuration specifications, optional header codecs for runtime parameters,
 * and symmetric key import/generation specifications. Key import
 * specifications are destroyable. The design favors safe defaults
 * (12-byte nonces, 128-bit AEAD tag), explicit role-to-context binding, and a
 * clear separation between static configuration and per-operation parameters.
 * </p>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>Algorithm descriptors:</b> {@link ChaChaAlgorithm} registers ENCRYPT
 * and DECRYPT roles for the ChaCha20 stream cipher;
 * {@link ChaCha20Poly1305Algorithm} registers the AEAD counterpart. Both share
 * a common base that wires symmetric key builders for generation and import.
 * </li>
 *
 * <li><b>Streaming contexts:</b> {@link ChaChaCipherContext} and
 * {@link ChaCha20Poly1305CipherContext} implement {@code InputStream}-to-
 * {@code InputStream} transforms. The abstract parent
 * {@link AbstractChaChaCipherContext} handles nonce lifecycle, optional header
 * injection/parsing, and construction of a pull-based cipher stream.</li>
 *
 * <li><b>Static configuration (specs):</b> {@link ChaChaSpec} captures the
 * initial counter and optional header codec for ChaCha20;
 * {@link ChaCha20Poly1305Spec} binds the optional header codec for AEAD. The
 * sealed marker {@link ChaChaBaseSpec} unifies both.</li>
 *
 * <li><b>Header codecs (optional):</b> {@link ChaChaHeaderCodec} writes/reads a
 * compact header carrying the 12-byte nonce and a packed stream counter;
 * {@link ChaCha20Poly1305HeaderCodec} writes/reads the 12-byte nonce and an
 * optional SHA-256 of AAD to assert out-of-band AAD integrity.</li>
 *
 * <li><b>Key specifications:</b> {@link ChaChaKeyGenSpec} defines parameters
 * for generating 256-bit ChaCha keys; {@link ChaChaKeyImportSpec} wraps
 * externally supplied raw keys. Generation and import are registered by the
 * algorithm base.</li>
 * </ul>
 *
 * <h2>Runtime parameters and context exchange</h2>
 * <p>
 * Streaming contexts exchange ephemeral parameters through a Conflux session
 * context using namespaced keys. Each ChaCha20 and ChaCha20-Poly1305 encryption
 * context is single-use: after an atomic claim it generates a fresh 12-byte
 * nonce and stores it back into the session. On decryption the nonce must
 * already be present and have the correct length. ChaCha20 also uses an initial
 * counter sourced from {@link ChaChaSpec} and optionally overridden by the
 * session context. When a header codec is configured and a session context is
 * set, encryption prepends a minimal header and decryption reads it first to
 * hydrate the session before initializing the cipher.
 * </p>
 *
 * <h2>Safety and validation</h2>
 * <ul>
 * <li><b>Nonce lifecycle:</b> Each encryption context is single-use and
 * generates its nonce internally after an atomic operation claim. Decryption
 * consumes the encoded or out-of-band nonce and fails if it is missing or has
 * an unexpected size.</li>
 *
 * <li><b>Counter policy (ChaCha20):</b> The default initial counter is 1. A
 * context may override the spec value through the session key dedicated to
 * counter exchange; consistency is enforced at attach time.</li>
 *
 * <li><b>AEAD tag and AAD (ChaCha20-Poly1305):</b> The effective tag length is
 * 128 bits. If AAD is supplied, it is included in authentication; when enabled,
 * the header codec can store SHA-256(AAD) to verify that decrypt-time AAD
 * matches encrypt-time AAD.</li>
 * </ul>
 *
 * <h2>Thread-safety</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share.</li>
 * <li>Streaming contexts are stateful and not thread-safe.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.chacha;
