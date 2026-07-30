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
 * Kyber (ML-KEM) post-quantum key encapsulation integration.
 *
 * <p>
 * This package wires the Kyber key encapsulation mechanism into the core layer.
 * It provides the algorithm descriptor, a lightweight runtime KEM context,
 * key-generation specifications for the supported Kyber variants, and encoded
 * key specs for import and export. Provider-specific details are kept behind
 * small factories while roles and metadata remain explicit to higher layers.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register Kyber under a canonical identifier and declare
 * {@link zeroecho.core.KeyUsage#ENCAPSULATE} and
 * {@link zeroecho.core.KeyUsage#DECAPSULATE} roles, with an optional
 * message-style agreement adapter where needed.</li>
 * <li>Provide a {@link zeroecho.core.context.KemContext} implementation bound
 * to either a public or private key for encapsulation or decapsulation.</li>
 * <li>Expose immutable key-generation specifications and defensively copying
 * encoded-key carriers with compact marshalling helpers; private-key carriers
 * are destroyable.</li>
 * <li>Ensure operations are delegated to an available PQC provider and fail
 * fast if the provider is absent.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>KyberAlgorithm:</b> algorithm descriptor that wires KEM and, when
 * required, message-agreement roles and registers asymmetric key builders for
 * generation and encoded-key import.</li>
 * <li><b>KyberKemContext:</b> runtime context implementing encapsulate and
 * decapsulate operations via provider primitives.</li>
 * <li><b>KyberKeyGenSpec:</b> immutable specification of the Kyber variant
 * (512, 768, 1024) with convenience factories.</li>
 * <li><b>KyberPublicKeySpec</b> and <b>KyberPrivateKeySpec:</b> wrappers over
 * X.509 and PKCS#8 encodings with defensive copying and simple marshalling
 * utilities.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share across
 * threads.</li>
 * <li>KEM contexts are stateful and not thread-safe; create one per
 * encapsulation or decapsulation operation.</li>
 * <li>Key specifications preserve encoded form without internal parsing and
 * rely on defensive cloning for safety.</li>
 * <li>Agreement adapters allow Kyber to be composed into initiator/responder
 * exchanges when a message-based interface is preferred.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.kyber;
