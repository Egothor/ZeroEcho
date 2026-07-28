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
 * ElGamal asymmetric encryption integration.
 *
 * <p>
 * This package provides the ElGamal algorithm descriptor, a streaming cipher
 * context, configuration specifications for padding and parameters, and encoded
 * key specifications for import/export. Provider-specific details are kept
 * behind small factories while roles and metadata remain explicit to higher
 * layers.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register ElGamal under a canonical identifier and declare
 * {@link zeroecho.core.KeyUsage#ENCRYPT} and
 * {@link zeroecho.core.KeyUsage#DECRYPT} roles.</li>
 * <li>Offer a streaming {@link zeroecho.core.context.EncryptionContext} that
 * performs block-wise ElGamal transforms with selectable padding.</li>
 * <li>Expose specifications for padding modes and for explicit domain
 * parameters, plus utility specs for encoded key import.</li>
 * <li>Encapsulate JCA/JCE interop and provider checks inside the algorithm
 * descriptor and builders.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>ElgamalAlgorithm</b>: algorithm descriptor that wires roles to the
 * streaming cipher context and registers key builders for explicit parameter
 * sets and encoded keys.</li>
 * <li><b>ElgamalCipherContext</b>: streaming context that encrypts or decrypts
 * data using ElGamal with block geometry derived from the modulus size and
 * selected padding.</li>
 * <li><b>ElgamalEncSpec</b>: immutable padding specification selecting either
 * no padding or PKCS#1 v1.5-style padding.</li>
 * <li><b>ElgamalParamSpec</b>: immutable wrapper for explicit domain parameters
 * (modulus and generator), including a predefined RFC 7919 FFDHE2048 set.</li>
 * <li><b>ElgamalKeyGenSpec</b>: parameters for generating fresh domain
 * parameters and key pairs; typically disabled in favor of predefined parameter
 * sets.</li>
 * <li><b>ElgamalPublicKeySpec</b> / <b>ElgamalPrivateKeySpec</b>: encoded key
 * specifications (X.509 and PKCS#8) with defensive copying and compact
 * marshalling helpers; the private-key form is destroyable.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and thread-safe; cipher contexts are
 * stateful and not thread-safe.</li>
 * <li>Padding choice affects plaintext-per-block and security properties;
 * modern protocols should prefer KEM-based constructions for IND-CCA
 * security.</li>
 * <li>Encoded key specs clone input and output arrays to avoid leaking internal
 * state.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.elgamal;
