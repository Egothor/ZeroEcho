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
package zeroecho.core.context;

import zeroecho.core.tag.TagEngine;

/**
 * Context for computing unkeyed message digests and extendable-output functions
 * (XOFs) in streaming pipelines.
 *
 * <p>
 * A {@code DigestContext} combines digest/XOF state with the {@link TagEngine}
 * contract: the wrapped input stream passes bytes through while updating the
 * computation; at end-of-file, a fixed-length tag is appended (produce mode) or
 * compared with an expected tag (verify mode).
 * </p>
 *
 * <h2>Operation</h2>
 * <ul>
 * <li><b>Produce mode:</b> {@link TagEngine#wrap(java.io.InputStream)} emits
 * the original data, then appends the digest (or configured-length XOF output)
 * as a trailer.</li>
 * <li><b>Verify mode:</b> Provide the expected tag via
 * {@link TagEngine#setExpectedTag(byte[])}; the engine compares the computed
 * tag at EOF using the configured verification approach.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <h3>Digest trailer</h3> <pre>
 * {@code
 * TagEngine<byte[]> eng = TagEngineBuilder.digest(DigestSpec.sha256()).get();
 * try (java.io.InputStream in = eng.wrap(upstream)) {
 *     in.transferTo(out);
 * }
 * }
 * </pre>
 *
 * <h3>Detached verification</h3> <pre>
 * {@code
 * TagEngine<byte[]> eng = TagEngineBuilder.digest(DigestSpec.sha256()).get();
 * eng.setExpectedTag(expectedDigest);
 * try (java.io.InputStream in = eng.wrap(bodyWithoutTrailer)) {
 *     in.transferTo(java.io.OutputStream.nullOutputStream());
 * }
 * }
 * </pre>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Unkeyed digests do not provide authenticity; use {@link MacContext} or
 * {@link SignatureContext} for that.</li>
 * <li>For XOFs, choose an output length appropriate for your security
 * level.</li>
 * <li>Implementations are stateful and not guaranteed to be thread-safe.</li>
 * </ul>
 *
 * @since 1.0
 */
public non-sealed interface DigestContext extends TagEngine<byte[]>, CryptoContext {
}
