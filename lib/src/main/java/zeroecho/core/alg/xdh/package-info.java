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
 * XDH (X25519/X448) Diffie-Hellman key agreement integration.
 *
 * <p>
 * This package provides the XDH algorithm descriptor, an agreement context
 * backed by the JCA {@code KeyAgreement} API, a key-pair generator, and encoded
 * key specifications for import and export. It focuses on safe defaults and
 * clear separation between algorithm metadata, runtime contexts, and key
 * builders.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register a canonical XDH algorithm and declare the
 * {@link zeroecho.core.KeyUsage#AGREEMENT} role.</li>
 * <li>Expose a runtime agreement context that derives raw shared secrets
 * suitable for KDF input.</li>
 * <li>Provide key builders for generating key pairs and importing encoded
 * public/private keys.</li>
 * <li>Offer immutable key specifications that defensively copy encoded material
 * and support compact marshalling.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>XdhAlgorithm</b>: algorithm descriptor that binds the agreement role
 * to a generic JCA-backed context and wires key builders.</li>
 * <li><b>XdhKeyGenBuilder</b>: key-pair generator using
 * {@code KeyPairGenerator} with names supplied by the spec.</li>
 * <li><b>XdhSpec</b>: enumeration of supported variants (X25519, X448) acting
 * as both context spec and key-gen spec.</li>
 * <li><b>XdhPublicKeySpec</b> / <b>XdhPrivateKeySpec</b>: wrappers over X.509
 * and PKCS#8 encodings with defensive copying and simple marshalling
 * helpers.</li>
 * </ul>
 *
 * <h2>Behavior and notes</h2>
 * <ul>
 * <li>Agreement contexts require a local private key and a peer public key
 * before deriving the shared secret; callers must apply a KDF.</li>
 * <li>Algorithm descriptors are immutable and safe to share; contexts are
 * stateful and not thread-safe.</li>
 * <li>Provider selection follows standard JCA lookup unless a specific provider
 * is configured upstream.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.xdh;
