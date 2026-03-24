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
 * SPHINCS+ post-quantum signature integration.
 *
 * <p>
 * This package wires the SPHINCS+ stateless hash-based signature scheme into
 * the core. It provides the algorithm descriptor, a streaming signature context
 * that adapts JCA engines, key-pair generation facilities, and encoded key
 * specifications for import and export. Provider-specific details are
 * encapsulated behind small factories while roles and metadata remain explicit
 * to higher layers.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register a canonical SPHINCS+ algorithm and declare the SIGN and VERIFY
 * roles.</li>
 * <li>Offer a streaming signature context with a fixed tag length determined by
 * the key's parameter set.</li>
 * <li>Provide key builders for generating new key pairs and for importing
 * encoded public and private keys.</li>
 * <li>Expose immutable key specification types that defensively copy sensitive
 * material and support compact marshalling.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>SphincsPlusAlgorithm</b>: algorithm descriptor that binds roles to the
 * signature context and registers builders and specs.</li>
 * <li><b>SphincsPlusSignatureContext</b>: streaming sign/verify context;
 * determines fixed signature size from the key's parameter set.</li>
 * <li><b>SphincsPlusKeyGenBuilder</b> and <b>SphincsPlusKeyGenSpec</b>:
 * generator and specification for producing key pairs with selected
 * variants.</li>
 * <li><b>SphincsPlusPublicKeyBuilder</b> / <b>SphincsPlusPrivateKeyBuilder</b>:
 * importers backed by JCA key factories.</li>
 * <li><b>SphincsPlusPublicKeySpec</b> / <b>SphincsPlusPrivateKeySpec</b>:
 * immutable wrappers over X.509 and PKCS#8 encodings with marshalling
 * helpers.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share; signature contexts
 * are stateful and not thread-safe.</li>
 * <li>Key specification classes never expose internal byte arrays; cloning is
 * used on input and output.</li>
 * <li>Marshalling helpers use a compact key-value form intended for
 * configuration, transport, and tests.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.sphincsplus;
