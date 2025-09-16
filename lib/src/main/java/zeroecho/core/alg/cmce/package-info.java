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
 * <h2>Classic McEliece (CMCE)</h2>
 *
 * <p>
 * This package integrates the Classic McEliece cryptosystem, one of the oldest
 * and most studied code-based public-key cryptosystems. Originally proposed by
 * Robert McEliece in 1978, it is based on the hardness of decoding random
 * binary Goppa codes. Despite large public key sizes, the scheme has withstood
 * decades of cryptanalysis and remains unbroken by both classical and quantum
 * computers.
 * </p>
 *
 * <h2>Post-quantum KEM</h2>
 *
 * <p>
 * Classic McEliece has been selected by NIST in the post-quantum cryptography
 * standardization process for key encapsulation. Its primary appeal is
 * long-term confidence: no efficient attacks are known even in the quantum
 * setting. It provides IND-CCA2 security through a well-studied transform and
 * is especially suited for use cases where large public keys are acceptable but
 * extremely strong security margins are desired.
 * </p>
 *
 * <h2>Contents</h2>
 * <ul>
 * <li>{@link zeroecho.core.alg.cmce.CmceAlgorithm} – algorithm adapter exposing
 * CMCE as a KEM and agreement primitive.</li>
 * <li>{@link zeroecho.core.alg.cmce.CmceKemContext} – runtime context for
 * encapsulation and decapsulation.</li>
 * <li>{@link zeroecho.core.alg.cmce.CmceKeyGenSpec} – enumeration of
 * standardized CMCE parameter sets (variants).</li>
 * <li>{@link zeroecho.core.alg.cmce.CmcePublicKeySpec} – wrapper for
 * X.509-encoded public keys.</li>
 * <li>{@link zeroecho.core.alg.cmce.CmcePrivateKeySpec} – wrapper for
 * PKCS#8-encoded private keys.</li>
 * </ul>
 *
 * <h2>Security properties</h2>
 * <ul>
 * <li>Underlying assumption: hardness of decoding binary Goppa codes.</li>
 * <li>Selected as a NIST post-quantum KEM standard (2022).</li>
 * <li>Public keys are large (hundreds of kilobytes), but ciphertexts and
 * secrets are compact.</li>
 * <li>Considered quantum-resistant and secure against known attacks.</li>
 * </ul>
 *
 * <h2>Usage</h2> <pre>{@code
 * // Select a variant (e.g., 8192128F for 256-bit security)
 * CmceKeyGenSpec spec = CmceKeyGenSpec.mceliece8192128f();
 * CmceAlgorithm alg = new CmceAlgorithm();
 * KeyPair kp = alg.asymmetricKeyBuilder(CmceKeyGenSpec.class).generateKeyPair(spec);
 *
 * // Encapsulation (sender)
 * try (CmceKemContext ctx = new CmceKemContext(alg, kp.getPublic())) {
 *   KemResult kem = ctx.encapsulate();
 *   byte[] ct = kem.ciphertext();
 *   byte[] secret = kem.secret();
 * }
 *
 * // Decapsulation (recipient)
 * try (CmceKemContext ctx = new CmceKemContext(alg, kp.getPrivate())) {
 *   byte[] secret = ctx.decapsulate(ct);
 * }
 * }</pre>
 *
 * @since 1.0
 */
package zeroecho.core.alg.cmce;
