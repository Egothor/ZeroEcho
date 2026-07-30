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
 * Ed25519 digital signature integration.
 *
 * <p>
 * This package wires the Ed25519 signature scheme into the core layer. It
 * provides the algorithm descriptor, a streaming signature context with a fixed
 * tag length, builders for generating and importing keys, and compact key
 * specifications for marshalling and transport.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register the Ed25519 algorithm and declare SIGN and VERIFY roles with
 * fixed-length signatures.</li>
 * <li>Provide a streaming signature context that adapts JCA engines and
 * enforces the 64-byte tag size.</li>
 * <li>Expose builders for key-pair generation and for importing encoded
 * public/private keys.</li>
 * <li>Define defensively copying key specifications suitable for safe cloning
 * and simple marshalling; private-key specifications are destroyable.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>Ed25519Algorithm</b>: algorithm descriptor that binds roles to a
 * signature context and registers builders for key generation and import.</li>
 * <li><b>Ed25519SignatureContext</b>: streaming context for signing and
 * verification with a fixed 64-byte tag.</li>
 * <li><b>Ed25519KeyGenBuilder</b> and <b>Ed25519KeyGenSpec</b>: generator and
 * marker spec for producing key pairs.</li>
 * <li><b>Ed25519PublicKeyBuilder</b> / <b>Ed25519PrivateKeyBuilder</b>:
 * importers backed by JCA key factories.</li>
 * <li><b>Ed25519PublicKeySpec</b> / <b>Ed25519PrivateKeySpec</b>: wrappers over
 * X.509 and PKCS#8 encodings, with defensive copying and simple base64
 * marshalling helpers; the private-key form is destroyable.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and thread-safe.</li>
 * <li>Signature contexts are stateful and not thread-safe; create a new
 * instance per operation.</li>
 * <li>Key specification classes never expose internal byte arrays; cloning is
 * used on input and output.</li>
 * <li>Marshalling helpers use a compact key-value form intended for
 * configuration, transport, and tests.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.ed25519;
