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
 * SABER post-quantum key encapsulation integration.
 *
 * <p>
 * This package wires the SABER KEM into the core layer. It provides the
 * algorithm descriptor, a runtime KEM context, a key-generation specification
 * selecting parameter variants, and encoded key specifications for import and
 * export. Provider details are encapsulated behind small factories while roles
 * and metadata remain explicit to higher layers.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register SABER under a canonical identifier and declare ENCAPSULATE and
 * DECAPSULATE roles, with an optional message-style agreement adapter built on
 * KEM.</li>
 * <li>Provide a {@link zeroecho.core.context.KemContext} bound to a public key
 * (encapsulation) or a private key (decapsulation).</li>
 * <li>Expose immutable specifications for key generation and encoded-key
 * carriers with compact marshalling helpers.</li>
 * <li>Validate presence of a suitable PQC provider before performing
 * operations.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>SaberAlgorithm</b>: algorithm descriptor that wires KEM and, when
 * needed, a message-agreement adapter, and registers asymmetric key
 * builders.</li>
 * <li><b>SaberKemContext</b>: runtime context implementing encapsulate and
 * decapsulate using provider primitives.</li>
 * <li><b>SaberKeyGenSpec</b>: immutable selection of SABER parameter variants
 * with simple factory methods.</li>
 * <li><b>SaberPublicKeySpec</b> and <b>SaberPrivateKeySpec</b>: wrappers over
 * X.509 and PKCS#8 encodings with defensive copying and marshalling
 * helpers.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share across
 * threads.</li>
 * <li>KEM contexts are stateful and not thread-safe; create one per
 * operation.</li>
 * <li>Key specifications preserve the provided encodings without internal
 * parsing and clone byte arrays on input and output.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.saber;
