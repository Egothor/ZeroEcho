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
 * RSA encryption and signature integration.
 *
 * <p>
 * This package wires RSA into the core layer, covering asymmetric encryption
 * (OAEP or PKCS#1 v1.5) and digital signatures (PKCS#1 v1.5 or RSASSA-PSS). It
 * provides the algorithm descriptor, streaming contexts for cipher and
 * signature operations, small utilities for block sizing, and key
 * specifications for generation and encoded-key import.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register RSA with roles for ENCRYPT/DECRYPT and SIGN/VERIFY and expose
 * defaults that favor OAEP (SHA-256) and PSS (SHA-256).</li>
 * <li>Provide streaming contexts that attach to input streams and transform
 * data on-the-fly without buffering entire messages.</li>
 * <li>Expose immutable specifications for cipher padding, signature mode and
 * hashing, and key generation parameters.</li>
 * <li>Offer encoded key specs for X.509 (public) and PKCS#8 (private) with
 * defensive copying and compact marshalling helpers.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>RsaAlgorithm</b>: algorithm descriptor that declares capabilities,
 * selects secure defaults, and registers key builders.</li>
 * <li><b>RsaCipherContext</b>: streaming encryption/decryption context that
 * initializes an RSA cipher according to {@code RsaEncSpec} and enforces block
 * geometry.</li>
 * <li><b>RsaSignatureContext</b>: streaming sign/verify context driven by
 * {@code RsaSigSpec}, emitting a trailer in SIGN mode or verifying at
 * end-of-stream in VERIFY mode.</li>
 * <li><b>BlockGeometry</b>: utility describing per-block input/output sizes
 * derived from modulus length, padding, and direction.</li>
 * <li><b>RsaEncSpec</b>: cipher specification (OAEP with selectable hash and
 * optional label, or PKCS#1 v1.5).</li>
 * <li><b>RsaSigSpec</b>: signature specification (PKCS#1 v1.5 or PSS with
 * selectable hash and salt length).</li>
 * <li><b>RsaKeyGenSpec</b>: key generation parameters (modulus size and public
 * exponent).</li>
 * <li><b>RsaPublicKeySpec</b> and <b>RsaPrivateKeySpec</b>: encoded-key
 * carriers for import/export.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and thread-safe.</li>
 * <li>Streaming contexts are stateful and not thread-safe; create a new
 * instance per pipeline.</li>
 * <li>Defaults prioritize modern schemes (OAEP, PSS). Legacy PKCS#1 v1.5 is
 * available primarily for interoperability and should be used with care.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.rsa;
