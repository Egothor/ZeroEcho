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
 * BIKE post-quantum key encapsulation and related utilities.
 *
 * <p>
 * This package integrates the BIKE (Bit Flipping Key Encapsulation) algorithm
 * into the core layer. It defines the algorithm descriptor, the runtime context
 * for encapsulation and decapsulation, and key specifications for generation
 * and import. The implementation relies on a Post-Quantum JCA provider and
 * focuses on safe, explicit wiring of roles, contexts, and key builders.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Expose a concrete algorithm descriptor that registers BIKE roles and key
 * builders.</li>
 * <li>Provide a runtime context that performs encapsulation and
 * decapsulation.</li>
 * <li>Define key specifications for generation and for importing encoded
 * keys.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>Algorithm descriptor:</b> {@link BikeAlgorithm} declares KEM roles for
 * encapsulation and decapsulation, wires a message-agreement adapter built on
 * KEM, and registers asymmetric key builders for BIKE key specs.</li>
 * <li><b>Runtime context:</b> {@link BikeKemContext} implements the key
 * encapsulation mechanism and separates encapsulation from decapsulation by
 * constructor selection.</li>
 * <li><b>Key generation spec:</b> {@link BikeKeyGenSpec} selects a BIKE variant
 * and is used by the key-pair builder.</li>
 * <li><b>Key import specs:</b> {@link BikePublicKeySpec} and
 * {@link BikePrivateKeySpec} wrap X.509 and PKCS#8 encodings and support
 * marshalling for transport and storage.</li>
 * </ul>
 *
 * <h2>Provider requirements</h2>
 * <p>
 * BIKE operations require a Post-Quantum JCA provider. The algorithm descriptor
 * expects the BouncyCastle PQC provider to be present and may validate provider
 * availability during key operations. Applications must ensure the provider is
 * installed before use.
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
package zeroecho.core.alg.bike;
