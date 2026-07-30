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
 * Hybrid signature composition for streaming pipelines.
 *
 * <p>
 * This package provides SDK-level hybrid signatures that combine two
 * independent signature schemes (typically a classical and a post-quantum
 * algorithm) and expose them as a single streaming signature engine suitable
 * for {@link zeroecho.sdk.builders.TagTrailerDataContentBuilder} and related
 * pipeline stages.
 * </p>
 *
 * <h2>Concept</h2>
 * <p>
 * A hybrid signature computes two component signatures over the same message
 * stream and then aggregates verification according to a configured rule:
 * </p>
 * <ul>
 * <li><b>AND</b> - verification succeeds only if both component signatures
 * verify.</li>
 * <li><b>OR</b> - verification succeeds if at least one component signature
 * verifies.</li>
 * </ul>
 *
 * <p>
 * The AND rule is intended for security-hardening scenarios (both schemes must
 * hold). The OR rule is intended for migration/fallback scenarios (accept if at
 * least one scheme verifies), and should be used with clear policy and
 * operational intent.
 * </p>
 *
 * <h2>Main types</h2>
 * <ul>
 * <li>{@link zeroecho.sdk.hybrid.signature.HybridSignatureProfile} - immutable
 * configuration describing the two component algorithms, optional per-algorithm
 * specs, and the verification rule.</li>
 * <li>{@link zeroecho.sdk.hybrid.signature.HybridSignatureContexts} - factory
 * methods for creating hybrid signing and verification contexts from keys and a
 * {@link zeroecho.sdk.hybrid.signature.HybridSignatureProfile}.</li>
 * <li>{@link zeroecho.sdk.hybrid.signature.HybridSignatureContext} - the
 * streaming hybrid {@link zeroecho.core.context.SignatureContext}
 * implementation that computes/verifies two signatures in a single pass.</li>
 * </ul>
 *
 * <h2>Integration with pipeline builders</h2>
 * <p>
 * The hybrid signature contexts created by this package are intended to be used
 * as engines in trailer-oriented pipeline stages. In particular:
 * </p>
 * <ul>
 * <li>{@link zeroecho.sdk.builders.SignatureTrailerDataContentBuilder} can
 * construct hybrid contexts directly and is the preferred signature-specialized
 * builder API.</li>
 * <li>{@link zeroecho.sdk.builders.TagTrailerDataContentBuilder} can also be
 * used with a hybrid {@link zeroecho.core.context.SignatureContext} when
 * generic tag handling is desired.</li>
 * </ul>
 *
 * <h2>Streaming and resource management</h2>
 * <p>
 * Hybrid signature computation and verification are streaming operations. The
 * resulting contexts and streams must be closed to release resources and to
 * finalize tag/signature production or verification.
 * </p>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>Hybrid verification should be configured explicitly for mismatch handling
 * (throw-on-mismatch vs. capture/flag) at the pipeline layer. This package
 * focuses on computing/verifying the two component signatures and returning an
 * aggregated result.</li>
 * <li>Implementations must not log or otherwise expose sensitive material
 * (private keys, seeds, message contents, intermediate state).</li>
 * </ul>
 *
 * <h2>Thread safety</h2>
 * <p>
 * Context instances are not thread-safe and are intended for single-use in a
 * single pipeline execution. Create a new context instance for each independent
 * signing or verification operation.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.sdk.hybrid.signature;
