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
 * HQC post-quantum key encapsulation integration.
 *
 * <p>
 * This package integrates the HQC (Hamming Quasi-Cyclic) KEM into the core
 * layer. It provides the algorithm descriptor, a runtime KEM context, and key
 * specifications for generation and import. Provider-specific details are
 * encapsulated behind small factories, while roles and metadata remain explicit
 * to higher layers.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register HQC under a canonical identifier and declare ENCAPSULATE and
 * DECAPSULATE roles, plus an agreement adapter for initiator and responder
 * workflows.</li>
 * <li>Provide a {@link zeroecho.core.context.KemContext} bound to a public or
 * private key for encapsulation or decapsulation.</li>
 * <li>Expose immutable key-generation specifications and defensively copying
 * encoded-key carriers with simple marshalling helpers; private-key carriers
 * are destroyable.</li>
 * <li>Ensure operations use a supported PQC provider and fail fast if the
 * provider is absent.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>HqcAlgorithm</b>: algorithm descriptor wiring KEM and agreement roles
 * and registering key builders.</li>
 * <li><b>HqcKemContext</b>: runtime context implementing encapsulate and
 * decapsulate operations.</li>
 * <li><b>HqcKeyGenSpec</b>: specification of HQC variants (128, 192, 256) with
 * convenience factories.</li>
 * <li><b>HqcPublicKeySpec</b> and <b>HqcPrivateKeySpec</b>: wrappers over X.509
 * and PKCS#8 encodings, with defensive copying and compact marshalling
 * utilities.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share across
 * threads.</li>
 * <li>KEM contexts are stateful and not thread-safe; use one context per
 * operation.</li>
 * <li>Encoded key specs preserve the provided encodings without internal
 * parsing and clone byte arrays on input and output.</li>
 * <li>Agreement adapters allow HQC to be composed into message-based exchanges
 * where needed.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.hqc;
