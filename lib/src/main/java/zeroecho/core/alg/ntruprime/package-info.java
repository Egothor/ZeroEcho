/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
/**
 * NTRU Prime family key encapsulation mechanisms and related utilities.
 *
 * <p>
 * This package integrates the NTRU LPRime and SNTRU Prime post-quantum KEMs
 * into the core layer. It provides algorithm descriptors, runtime KEM contexts,
 * key generation specifications, and encoded key specifications for import and
 * export. Provider-specific details are encapsulated behind small factories
 * while roles and metadata remain explicit to higher layers.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register canonical algorithms for NTRU LPRime and SNTRU Prime and declare
 * ENCAPSULATE and DECAPSULATE roles, plus an agreement adapter that maps KEM to
 * a message-style initiator/responder API.</li>
 * <li>Provide {@link zeroecho.core.context.KemContext} implementations bound to
 * a public key (encapsulation) or a private key (decapsulation).</li>
 * <li>Expose immutable specifications for key generation variants and
 * encoded-key carriers with compact marshalling helpers.</li>
 * <li>Validate provider availability and fail fast if the PQC provider is
 * absent.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>NtrulPrimeAlgorithm</b> and <b>SntruPrimeAlgorithm</b>: algorithm
 * descriptors that wire KEM and agreement roles and register asymmetric key
 * builders for generation and encoded-key import.</li>
 * <li><b>NtrulPrimeKemContext</b> and <b>SntruPrimeKemContext</b>: runtime
 * contexts implementing encapsulate and decapsulate operations.</li>
 * <li><b>NtrulPrimeKeyGenSpec</b> / <b>SntruPrimeKeyGenSpec</b>: immutable
 * selection of standardized parameter variants with convenience factories.</li>
 * <li><b>NtrulPrimePublicKeySpec</b>, <b>NtrulPrimePrivateKeySpec</b>,
 * <b>SntruPrimePublicKeySpec</b>, <b>SntruPrimePrivateKeySpec</b>: wrappers
 * over X.509 and PKCS#8 encodings with defensive copying and simple marshalling
 * utilities.</li>
 * </ul>
 *
 * <h2>Provider requirements</h2>
 * <p>
 * All key operations rely on a PQC provider (Bouncy Castle PQC). The provider
 * must be installed in the current JVM before use; otherwise key generation and
 * import fail.
 * </p>
 *
 * <h2>Thread-safety</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share across
 * threads.</li>
 * <li>KEM contexts are stateful and not thread-safe; create one per
 * operation.</li>
 * <li>Encoded key specs clone input and output arrays to avoid leaking internal
 * state.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.ntruprime;
