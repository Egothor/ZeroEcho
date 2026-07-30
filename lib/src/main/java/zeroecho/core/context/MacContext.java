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

import zeroecho.core.tag.ByteVerificationStrategy;
import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.ThrowingBiPredicate;

/**
 * Context for computing message authentication codes (MACs) in streaming
 * pipelines.
 *
 * <p>
 * A {@code MacContext} encapsulates the state of a keyed integrity primitive
 * such as HMAC, KMAC, or CMAC and exposes the {@link TagEngine} contract: the
 * wrapped input stream passes bytes through while the MAC state is updated; at
 * end-of-file a fixed-length tag is either appended (produce mode) or compared
 * with an expected tag (verify mode).
 * </p>
 *
 * <h2>Operation</h2>
 * <ul>
 * <li><b>Produce mode:</b> {@link TagEngine#wrap(java.io.InputStream)} emits
 * the original data and then appends the computed MAC as a trailer.</li>
 * <li><b>Verify mode:</b> Supply the expected tag via
 * {@link TagEngine#setExpectedTag(byte[])} and ensure the upstream body does
 * not include a trailer. At EOF the computed tag is compared using the
 * configured verification approach set with
 * {@link TagEngine#setVerificationApproach(ThrowingBiPredicate.VerificationBiPredicate)}.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <h3>Produce an HMAC trailer</h3> <pre>
 * {@code
 * javax.crypto.SecretKey key = ...;
 * HmacSpec spec = HmacSpec.sha256();
 *
 * TagEngine<byte[]> eng = TagEngineBuilder.hmac(key, spec).get();
 * try (java.io.InputStream in = eng.wrap(upstream)) {
 *     in.transferTo(out); // body bytes, then HMAC trailer are written to 'out'
 * }
 * }
 * </pre>
 *
 * <h3>Verify a detached MAC</h3> <pre>
 * {@code
 * byte[] expectedMac = ...; // obtained via a trusted channel
 *
 * TagEngine<byte[]> eng = TagEngineBuilder.hmac(key, HmacSpec.sha256()).get();
 * // Optional: throw on mismatch instead of silent flagging
 * eng.setVerificationApproach(eng.getVerificationCore().getThrowOnMismatch());
 * eng.setExpectedTag(expectedMac);
 *
 * try (java.io.InputStream in = eng.wrap(bodyWithoutTrailer)) {
 *     in.transferTo(java.io.OutputStream.nullOutputStream()); // comparison at EOF
 * }
 * }
 * </pre>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>MACs are keyed and provide authenticity and integrity, unlike
 * {@link DigestContext}.</li>
 * <li>Comparisons should be constant time. Use a strategy such as
 * {@link ByteVerificationStrategy} via
 * {@link TagEngine#setVerificationApproach(ThrowingBiPredicate.VerificationBiPredicate)}.</li>
 * <li>Instances are stateful and not thread-safe. Use one context per
 * pipeline.</li>
 * </ul>
 *
 * @since 1.0
 */
public non-sealed interface MacContext extends TagEngine<byte[]>, CryptoContext {
}
