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
 * HMAC algorithms, streaming MAC contexts, and key specifications.
 *
 * <p>
 * This package integrates Hash-based Message Authentication Code (HMAC) into
 * the core layer. It provides the algorithm descriptor, a streaming MAC context
 * that can produce or verify tags, operation specifications for choosing the
 * digest family, and key specifications for generation and import.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Register a canonical HMAC algorithm and declare the
 * {@link zeroecho.core.KeyUsage#MAC} role.</li>
 * <li>Expose a streaming {@link zeroecho.core.context.MacContext} that appends
 * tags in produce mode or verifies an expected tag at end of stream in verify
 * mode.</li>
 * <li>Provide immutable specs for selecting the HMAC variant and destroyable
 * specs for importing raw key material.</li>
 * <li>Encapsulate JCA/JCE interop and provider checks behind small
 * factories.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>HmacAlgorithm</b>: algorithm descriptor that wires the MAC role to a
 * streaming context and registers symmetric key builders for generation and
 * import.</li>
 * <li><b>HmacMacContext</b>: streaming MAC context backed by
 * {@link javax.crypto.Mac}; supports produce and verify modes under a clear
 * verification policy.</li>
 * <li><b>HmacSpec</b>: operation specification selecting the HMAC variant
 * (e.g., SHA-256/384/512).</li>
 * <li><b>HmacKeyGenSpec</b>: parameters for generating secret keys for a
 * specific HMAC variant.</li>
 * <li><b>HmacKeyImportSpec</b>: wrapper for importing existing raw keys, with
 * Base64/hex helpers.</li>
 * <li><b>HmacStream</b>: internal passthrough input stream implementing the
 * byte-pumping and trailer/verification logic for the MAC context.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm descriptors are immutable and safe to share.</li>
 * <li>Streaming contexts are stateful and not thread-safe; use a new instance
 * per wrapped stream.</li>
 * <li>Key specification classes defensively copy input and output byte
 * arrays.</li>
 * <li>Verification behavior is explicit: failures either throw or are recorded
 * in a caller-provided context.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.hmac;
