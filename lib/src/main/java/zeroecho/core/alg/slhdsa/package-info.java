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
 * SLH-DSA (FIPS&nbsp;205) signature algorithm binding.
 *
 * <p>
 * This package provides a ZeroEcho binding for <em>SLH-DSA</em>, the
 * NIST-standardized profile of the stateless hash-based signature scheme
 * SPHINCS+. While SLH-DSA is derived from SPHINCS+, it is exposed here as a
 * distinct algorithm identity with a restricted, standards-compliant parameter
 * space.
 * </p>
 *
 * <h2>Algorithm identity</h2>
 * <ul>
 * <li>JCA algorithm name: {@code "SLH-DSA"}</li>
 * <li>ZeroEcho algorithm id: {@code "SLHDSA"}</li>
 * <li>Provider: Bouncy Castle core provider ({@code "BC"})</li>
 * </ul>
 *
 * <h2>Supported parameter space</h2>
 * <p>
 * The supported parameters correspond exactly to the SLH-DSA profiles defined
 * by FIPS&nbsp;205:
 * </p>
 * <ul>
 * <li>Hash families: SHA2 and SHAKE</li>
 * <li>Security levels: 128, 192, 256 bits (NIST levels L1, L3, L5)</li>
 * <li>Variants: {@code FAST} (larger, faster signatures) and {@code SMALL}
 * (smaller, slower signatures)</li>
 * <li>Optional pre-hash variants as defined by the standard and exposed by the
 * provider</li>
 * </ul>
 *
 * <p>
 * Non-standard SPHINCS+ variants (e.g. Haraka, simple/robust modes) are
 * intentionally excluded from this package.
 * </p>
 *
 * <h2>Key management</h2>
 * <ul>
 * <li>Key generation is configured via
 * {@link zeroecho.core.alg.slhdsa.SlhDsaKeyGenSpec} and performed by
 * {@link zeroecho.core.alg.slhdsa.SlhDsaKeyGenBuilder}.</li>
 * <li>Encoded public and private keys are represented by
 * {@link zeroecho.core.alg.slhdsa.SlhDsaPublicKeySpec} and
 * {@link zeroecho.core.alg.slhdsa.SlhDsaPrivateKeySpec}.</li>
 * <li>All key specifications are immutable and use defensive copies.</li>
 * </ul>
 *
 * <h2>Streaming signature model</h2>
 * <p>
 * Signatures are processed through the ZeroEcho streaming signature
 * infrastructure:
 * </p>
 * <ul>
 * <li>In {@link zeroecho.core.KeyUsage#SIGN} mode, the signature is appended as
 * a fixed-length trailer to the output stream.</li>
 * <li>In {@link zeroecho.core.KeyUsage#VERIFY} mode, the wrapped stream emits
 * only the message body; verification is performed at end-of-stream against a
 * caller-supplied expected signature.</li>
 * </ul>
 *
 * <p>
 * The canonical signature length is derived from the public key parameters by
 * {@link zeroecho.core.alg.slhdsa.SlhDsaSignatureContext} and matches the
 * standard SLH-DSA signature sizes defined by FIPS&nbsp;205.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>No sensitive material (private keys, signatures, message contents) is
 * logged or exposed by this package.</li>
 * <li>All byte arrays returned to callers are defensive copies.</li>
 * <li>Verification failures are surfaced exclusively via the configured
 * verification strategy.</li>
 * </ul>
 *
 * <h2>Relationship to SPHINCS+</h2>
 * <p>
 * The {@code slhdsa} package represents the standardized SLH-DSA profile only.
 * A separate {@code sphincsplus} package may expose the full SPHINCS+ design
 * space and experimental variants. No API-level equivalence between the two
 * packages is assumed.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.core.alg.slhdsa;
