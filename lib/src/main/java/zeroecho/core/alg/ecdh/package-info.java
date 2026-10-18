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
 * Elliptic Curve Diffie-Hellman (ECDH) key agreement integration.
 *
 * <p>
 * This package provides the ECDH algorithm descriptor, named-curve selection,
 * and a key-pair builder backed by the JCA. It wires ECDH into the core
 * agreement SPI through a generic JCA-based agreement context and reuses EC key
 * importers shared with ECDSA where appropriate.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register a canonical ECDH algorithm and declare its agreement
 * capability.</li>
 * <li>Expose a curve specification for standard NIST curves suitable for
 * ECDH.</li>
 * <li>Provide a key-pair builder that generates EC keys on the selected curve
 * using JCA primitives.</li>
 * <li>Reuse EC public/private key importers to avoid duplication.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>EcdhAlgorithm:</b> registers the {@code "ECDH"} algorithm, binds the
 * agreement capability to a JCA-backed context, and wires EC key
 * builders/importers.</li>
 * <li><b>EcdhCurveSpec:</b> immutable enum of named curves providing the JCA
 * curve name and auxiliary metadata.</li>
 * <li><b>EcdhKeyGenBuilder:</b> generates EC key pairs for ECDH on the
 * requested curve.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and thread-safe; agreement contexts
 * they produce are stateful and not thread-safe.</li>
 * <li>Key import paths are shared between ECDH and ECDSA, as the encoding and
 * curve parameters are identical at the key level.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.ecdh;
