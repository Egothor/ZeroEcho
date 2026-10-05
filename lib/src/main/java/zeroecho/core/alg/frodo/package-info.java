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
 * FrodoKEM post-quantum key encapsulation integration.
 *
 * <p>
 * This package integrates the Frodo lattice-based key encapsulation mechanism
 * (KEM) into the core layer. It provides the algorithm descriptor, runtime KEM
 * context, key generation specifications, and encoded key specs for import and
 * export. Frodo is based on the hardness of the Learning With Errors (LWE)
 * problem, avoiding structured lattices and offering conservative security
 * margins.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register Frodo under a canonical identifier and declare
 * {@link zeroecho.core.KeyUsage#ENCAPSULATE} and
 * {@link zeroecho.core.KeyUsage#DECAPSULATE} roles, plus an agreement adapter
 * role for initiator/responder workflows.</li>
 * <li>Provide a {@link zeroecho.core.context.KemContext} implementation bound
 * to either a public or private key for encapsulation or decapsulation.</li>
 * <li>Expose immutable key-generation specifications and defensively copying
 * encoded-key carriers with marshalling helpers; private-key carriers are
 * destroyable.</li>
 * <li>Ensure operations are delegated to a supported PQC provider (BouncyCastle
 * PQC) and fail fast if absent.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>FrodoAlgorithm:</b> algorithm descriptor that wires KEM and agreement
 * roles and registers key builders.</li>
 * <li><b>FrodoKemContext:</b> runtime context implementing encapsulate and
 * decapsulate operations using BouncyCastle’s Frodo engine.</li>
 * <li><b>FrodoKeyGenSpec:</b> immutable specification of the Frodo variant
 * (976, 1344; AES or SHAKE-based), with convenience factories.</li>
 * <li><b>FrodoPublicKeySpec</b> / <b>FrodoPrivateKeySpec:</b> wrappers over
 * X.509 and PKCS#8 encodings with defensive copying and
 * {@link zeroecho.core.marshal.PairSeq} marshalling utilities.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share across
 * threads.</li>
 * <li>KEM contexts are stateful and not thread-safe; they are intended for
 * single encapsulation or decapsulation operations.</li>
 * <li>Key specifications preserve encoded form without internal parsing and
 * rely on defensive cloning for safety.</li>
 * <li>Agreement adapters allow FrodoKEM to be composed into higher-level
 * initiator/responder protocols transparently.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.frodo;
