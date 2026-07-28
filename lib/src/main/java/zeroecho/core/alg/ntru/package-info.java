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
 * NTRU post-quantum key encapsulation integration.
 *
 * <p>
 * This package wires the NTRU KEM into the core layer. It provides the
 * algorithm descriptor, a runtime KEM context, a key generation specification
 * selecting parameter sets, and encoded key specifications for import and
 * export. Provider specifics are kept behind small factories while roles and
 * metadata remain explicit for higher layers.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register NTRU under a canonical identifier and declare ENCAPSULATE and
 * DECAPSULATE roles, with an optional message-style agreement adapter.</li>
 * <li>Provide a {@link zeroecho.core.context.KemContext} bound to either a
 * public key (encapsulation) or a private key (decapsulation).</li>
 * <li>Expose immutable key-generation specifications and defensively copying
 * encoded-key carriers with simple marshalling helpers; private-key carriers
 * are destroyable.</li>
 * <li>Validate the presence of a suitable PQC provider before performing JCA
 * operations.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>NtruAlgorithm</b>: algorithm descriptor that wires KEM and optional
 * agreement roles and registers asymmetric key builders for generation and
 * encoded-key import.</li>
 * <li><b>NtruKemContext</b>: runtime context that performs encapsulation and
 * decapsulation using provider primitives.</li>
 * <li><b>NtruKeyGenSpec</b>: immutable selection of NTRU variants from HPS and
 * HRSS families, with convenience factories.</li>
 * <li><b>NtruPublicKeySpec</b> and <b>NtruPrivateKeySpec</b>: wrappers over
 * X.509 and PKCS#8 encodings with defensive copying and compact marshalling
 * utilities.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share across
 * threads.</li>
 * <li>KEM contexts are stateful and not thread-safe; create one per
 * operation.</li>
 * <li>Encoded key specs preserve the provided encodings without internal
 * parsing and clone byte arrays on input and output.</li>
 * <li>An agreement adapter allows NTRU KEM to participate in initiator and
 * responder exchanges through a message-based interface when needed.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.ntru;
