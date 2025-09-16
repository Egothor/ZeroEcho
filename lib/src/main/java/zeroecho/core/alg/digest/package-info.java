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
 * Digest algorithms (SHA-2, SHA-3, SHAKE) and their streaming contexts.
 *
 * <p>
 * This package provides the core unkeyed hash functions of the ZeroEcho
 * library. It integrates JCA {@link java.security.MessageDigest} engines into
 * the framework’s streaming context model, allowing digests to be applied as
 * pipeline stages with produce/verify modes. It also defines immutable
 * specifications for selecting digest variants and output lengths for
 * extendable-output functions.
 * </p>
 *
 * <h2>Scope and responsibilities</h2>
 * <ul>
 * <li>Expose a single algorithm descriptor under id {@code "DIGEST"} that
 * covers SHA-2, SHA-3, and SHAKE variants.</li>
 * <li>Provide a JCA-backed {@link zeroecho.core.context.DigestContext} for
 * streaming input through a {@link java.security.MessageDigest} engine.</li>
 * <li>Support both fixed-length digests and extendable-output functions (XOFs)
 * with configurable output size.</li>
 * <li>Ensure interoperability with JCA provider implementations.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>Sha2Sha3Algorithm</b>: registers the algorithm, declares its digest
 * capability, and creates contexts bound to the appropriate JCA
 * {@link java.security.MessageDigest}.</li>
 * <li><b>DigestSpec</b>: immutable specification of digest variant and output
 * length (for XOFs); provides static factories for common cases.</li>
 * <li><b>JcaDigestContext</b>: streaming digest context that adapts
 * {@link java.security.MessageDigest} to the core SPI, supporting produce
 * (append digest) and verify (check expected tag) modes.</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Algorithm instances are immutable and thread-safe for reuse.</li>
 * <li>Context instances are stateful and not thread-safe; create a new context
 * for each pipeline.</li>
 * <li>Verification policies integrate with the tagging engine to either throw
 * on mismatch or set a flag in the context.</li>
 * <li>Extendable-output functions require explicit output lengths; fixed
 * digests derive their size from the algorithm.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.digest;
