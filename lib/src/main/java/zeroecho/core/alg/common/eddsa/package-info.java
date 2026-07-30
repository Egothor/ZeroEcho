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
 */
/**
 * EdDSA (Edwards-curve Digital Signature Algorithm) key builders and contexts.
 *
 * <p>
 * This package provides common infrastructure for Ed25519 and Ed448 algorithm
 * support. It focuses on key-pair generation, importing encoded keys, and
 * wiring EdDSA variants into the generic signature context API.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Provide abstract builders for EdDSA key-pair generation and encoded key
 * import.</li>
 * <li>Offer an abstract signature context that binds an EdDSA variant to the
 * generic JCA-based signature context, with fixed tag lengths.</li>
 * <li>Keep provider-specific concerns encapsulated in small, composable
 * building blocks.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>Key generation:</b>
 * {@link zeroecho.core.alg.common.eddsa.AbstractEdDSAKeyGenBuilder} integrates
 * with {@link java.security.KeyPairGenerator} to produce new Ed25519/Ed448 key
 * pairs.</li>
 * <li><b>Private key import:</b>
 * {@link zeroecho.core.alg.common.eddsa.AbstractEncodedPrivateKeyBuilder}
 * reconstructs private keys from PKCS#8 encodings via
 * {@link java.security.KeyFactory}.</li>
 * <li><b>Public key import:</b>
 * {@link zeroecho.core.alg.common.eddsa.AbstractEncodedPublicKeyBuilder}
 * reconstructs public keys from X.509 encodings via
 * {@link java.security.KeyFactory}.</li>
 * <li><b>Signature contexts:</b>
 * {@link zeroecho.core.alg.common.eddsa.CommonEdDSASignatureContext} delegates
 * all operations to a generic JCA-backed signature adapter, enforcing a fixed
 * tag length for the selected EdDSA variant.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Builders are stateless and safe for concurrent use; each import or
 * generation creates a fresh JCA engine internally.</li>
 * <li>Import methods intentionally throw for unsupported directions (e.g.,
 * public import in the private builder) to keep responsibilities clear.</li>
 * <li>Signature contexts are not thread-safe; they are expected to be used for
 * a single signing or verification stream at a time.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.common.eddsa;
