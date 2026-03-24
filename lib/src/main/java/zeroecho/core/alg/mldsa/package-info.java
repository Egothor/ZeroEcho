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
 * ML-DSA (FIPS&nbsp;204) signature algorithm binding.
 *
 * <p>
 * This package provides the ZeroEcho binding for <em>ML-DSA</em>
 * (Module-Lattice-Based Digital Signature Algorithm), standardized by NIST as
 * FIPS&nbsp;204. ML-DSA is derived from CRYSTALS-Dilithium and is exposed here
 * as a standards-compliant algorithm identity with a restricted parameter
 * space.
 * </p>
 *
 * <h2>Algorithm identity</h2>
 * <ul>
 * <li>JCA algorithm name: {@code "ML-DSA"}</li>
 * <li>ZeroEcho algorithm id: {@code "MLDSA"}</li>
 * <li>Provider: Bouncy Castle core provider ({@code "BC"})</li>
 * </ul>
 *
 * <h2>Supported parameter sets</h2>
 * <p>
 * The supported parameter sets are those defined by FIPS&nbsp;204: ML-DSA-44,
 * ML-DSA-65, and ML-DSA-87. Bouncy Castle exposes these via
 * {@code org.bouncycastle.jcajce.spec.MLDSAParameterSpec}.
 * </p>
 *
 * <h2>Streaming signature model</h2>
 * <ul>
 * <li>In {@link zeroecho.core.KeyUsage#SIGN} mode, the signature is appended as
 * a fixed-length trailer to the output stream.</li>
 * <li>In {@link zeroecho.core.KeyUsage#VERIFY} mode, the wrapped stream emits
 * only the message body and performs verification at end-of-stream against a
 * caller-supplied expected signature.</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>No sensitive material (private keys, signatures, message contents) is
 * logged by this package.</li>
 * <li>All externally returned byte arrays are defensive copies.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.mldsa;
