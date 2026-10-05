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
 * Classic McEliece (CMCE) KEM integration and utilities.
 *
 * <p>
 * This package adapts the Bouncy Castle PQC CMCE primitives to the core SPI. It
 * provides the algorithm descriptor, a runtime KEM context, and key
 * specifications for generation and import. The design keeps provider-specific
 * details encapsulated behind factories while exposing clear roles and metadata
 * to the higher layers.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Expose a concrete algorithm descriptor that registers CMCE KEM roles and
 * a KEM-backed message-agreement adapter.</li>
 * <li>Provide a runtime context that performs encapsulation and
 * decapsulation.</li>
 * <li>Define key specifications for key-pair generation and for importing X.509
 * and PKCS#8 encodings.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>Algorithm descriptor:</b> {@link zeroecho.core.alg.cmce.CmceAlgorithm}
 * declares {@code ENCAPSULATE}/{@code DECAPSULATE} KEM roles and wires an
 * {@code AGREEMENT} role through a KEM-based adapter. It also registers
 * asymmetric key builders for generation and import. The provider requirement
 * is the Bouncy Castle provider under the standard name
 * {@code "BC"}.</li>
 * <li><b>Runtime context:</b> {@link zeroecho.core.alg.cmce.CmceKemContext}
 * holds state for encapsulation or decapsulation depending on which constructor
 * is used.</li>
 * <li><b>Key generation spec:</b> {@link zeroecho.core.alg.cmce.CmceKeyGenSpec}
 * selects a CMCE parameter set (variant) used by the key-pair builder.</li>
 * <li><b>Key import specs:</b> {@link zeroecho.core.alg.cmce.CmcePublicKeySpec}
 * wraps X.509 public keys and {@link zeroecho.core.alg.cmce.CmcePrivateKeySpec}
 * wraps PKCS#8 private keys; both defensively copy their byte arrays, and the
 * private-key form is destroyable.</li>
 * </ul>
 *
 * <h2>Provider requirements</h2>
 * <p>
 * The algorithm expects the Bouncy Castle provider to be installed before
 * use; the descriptor verifies this when generating or importing keys.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share across
 * threads.</li>
 * <li>Runtime contexts are stateful and not thread-safe.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.cmce;
