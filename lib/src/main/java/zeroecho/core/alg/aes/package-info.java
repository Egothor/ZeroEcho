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
 * AES algorithm implementation and runtime wiring.
 *
 * <p>
 * This package provides the AES capability set for the core layer, including
 * the algorithm descriptor, a streaming cipher context for GCM / CBC / CTR,
 * static configuration, a minimal header codec for runtime parameters, and key
 * import/generation specifications. The design favors safe defaults (GCM with a
 * 128-bit tag), explicit role-to-context binding, and clear separation between
 * static configuration and per-operation parameters.
 * </p>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>Algorithm descriptor:</b> {@link AesAlgorithm} registers ENCRYPT and
 * DECRYPT roles, installs default specifications, and exposes symmetric key
 * builders for generation and import. Capabilities are published for discovery
 * by higher layers.</li>
 * <li><b>Streaming context:</b> {@link AesCipherContext} implements the runtime
 * transform over {@code InputStream}, handling IV creation and validation,
 * optional AAD, tag length (GCM), and mode-specific initialization.</li>
 * <li><b>Static configuration:</b> {@link AesSpec} captures compile-time
 * choices (mode, padding, tag length for GCM) and may embed a header codec used
 * by the context to persist runtime parameters in-band.</li>
 * <li><b>Header codec:</b> {@link AesHeaderCodec} writes/reads a compact header
 * containing IV, a tag-length hint for GCM, and an optional AAD hash used to
 * verify that decrypt-time AAD matches encrypt-time AAD.</li>
 * <li><b>Key specifications:</b> {@link AesKeyGenSpec} defines key-size
 * parameters for generation, and {@link AesKeyImportSpec} wraps existing AES
 * keys supplied as raw bytes, hex, or Base64.</li>
 * </ul>
 *
 * <h2>Runtime parameters and context exchange</h2>
 * <p>
 * The streaming context exchanges ephemeral parameters (IV/nonce, GCM tag bits,
 * and optional AAD) via a Conflux session context. When a header codec is
 * present and a session context is set, encryption prepends a minimal header
 * and decryption reads it first to hydrate the session context before
 * initializing the cipher.
 * </p>
 *
 * <h2>Safety and validation</h2>
 * <ul>
 * <li>GCM requires no padding and a tag length between 96 and 128 bits in 8-bit
 * steps; non-GCM modes must not specify a tag length.</li>
 * <li>IV length is enforced by mode (12 bytes for GCM; 16 bytes for CBC/CTR),
 * and decryption fails if IV is missing or has an unexpected size.</li>
 * <li>When an AAD hash is present in the header, decryption enforces
 * consistency with the caller-supplied AAD.</li>
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
package zeroecho.core.alg.aes;
