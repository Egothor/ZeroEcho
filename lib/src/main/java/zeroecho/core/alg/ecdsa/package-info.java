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
 * Elliptic Curve Digital Signature Algorithm (ECDSA) integration.
 *
 * <p>
 * This package provides the ECDSA algorithm descriptor, curve specifications,
 * key builders for generation and import, and defensively copying encoded key
 * specs. It wires ECDSA into the core signature SPI through a JCA-backed
 * streaming signature context that enforces fixed signature lengths.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register ECDSA under a canonical identifier and declare its
 * {@link zeroecho.core.KeyUsage#SIGN} and {@link zeroecho.core.KeyUsage#VERIFY}
 * roles.</li>
 * <li>Expose curve specifications for NIST P-256, P-384, and P-521 with
 * canonical curve names, JCA algorithm identifiers, and fixed tag lengths.</li>
 * <li>Provide key builders for generating EC key pairs and importing
 * X.509/PKCS#8 encodings.</li>
 * <li>Adapt JCA {@link java.security.Signature} engines to the core streaming
 * context model with strict length enforcement.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>EcdsaAlgorithm:</b> registers the algorithm, declares sign/verify
 * capabilities, and wires EC key builders and specs.</li>
 * <li><b>EcdsaCurveSpec:</b> enum of supported curves (P-256, P-384, P-521)
 * with curve names, JCA identifiers, and deterministic signature lengths.</li>
 * <li><b>EcdsaKeyGenBuilder:</b> generates EC key pairs for the chosen curve
 * using {@link java.security.KeyPairGenerator} with
 * {@link java.security.spec.ECGenParameterSpec}.</li>
 * <li><b>EcdsaPublicKeyBuilder</b> and <b>EcdsaPrivateKeyBuilder:</b> import
 * keys from X.509 and PKCS#8 encodings via
 * {@link java.security.KeyFactory}.</li>
 * <li><b>EcdsaPublicKeySpec</b> and <b>EcdsaPrivateKeySpec:</b> wrappers around
 * encoded keys with marshalling support; the private-key form is
 * destroyable.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and thread-safe; signature contexts
 * are stateful and not thread-safe.</li>
 * <li>Unsupported directions in key builders (e.g., generating from an import
 * spec) fail fast with clear exceptions.</li>
 * <li>Signatures are always encoded in IEEE P1363 format (R and S concatenated)
 * with deterministic lengths.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.ecdsa;
