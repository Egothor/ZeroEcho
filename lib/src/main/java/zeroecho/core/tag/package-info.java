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
 * Streaming tag computation and verification for digests, MACs, and digital
 * signatures.
 *
 * <p>
 * This package defines a minimal engine interface for tag-producing primitives
 * and a small builder that instantiates engines backed by registered
 * algorithms. Engines operate in a single-use, pipeline-friendly style: they
 * wrap an upstream stream, update internal state as bytes flow, and then either
 * append a fixed-length trailer (produce mode) or verify an expected tag
 * (verify mode) according to a configurable verification approach.
 * </p>
 *
 * <h2>Engines and verification</h2>
 * <p>
 * The core abstraction is {@link TagEngine}, which adapts stateful primitives
 * such as {@link java.security.MessageDigest}, {@link java.security.Signature},
 * or HMAC engines to a streaming model. Verification behavior is delegated to a
 * strategy implementing {@link ThrowingBiPredicate.VerificationBiPredicate},
 * enabling constant-time equality for byte arrays or delegation to a JCA
 * {@link java.security.Signature}. Callers can swap or decorate the strategy,
 * for example to throw on mismatch or to record the result in a context object.
 * </p>
 *
 * <h2>Operation modes</h2>
 * <ul>
 * <li><b>Produce mode</b>: {@link TagEngine#wrap(java.io.InputStream)} returns
 * a pass-through stream that emits the original data and, at end-of-stream,
 * appends the computed tag as a trailer.</li>
 * <li><b>Verify mode</b>: The caller supplies the expected tag via
 * {@link TagEngine#setExpectedTag(byte[])} and ensures the upstream body does
 * not include a trailer. At end-of-stream, the engine compares the computed tag
 * with the expected tag and reports the outcome using the configured
 * verification approach set via
 * {@link TagEngine#setVerificationApproach(ThrowingBiPredicate.VerificationBiPredicate)}.
 * </li>
 * </ul>
 *
 * <h2>Typical usage</h2>
 * <h3>Produce an HMAC trailer</h3> <pre>
 * {@code
 * javax.crypto.SecretKey key = ...;
 * HmacSpec spec = HmacSpec.sha256();
 *
 * TagEngine&lt;byte[]&gt; eng = TagEngineBuilder.hmac(key, spec).get();
 * try (java.io.InputStream in = eng.wrap(upstream)) {
 *     in.transferTo(out); // body bytes, then HMAC trailer are written to 'out'
 * }
 * }
 * </pre>
 *
 * <h3>Verify a detached signature and throw on mismatch</h3> <pre>
 * {@code
 * java.security.PublicKey pub = ...;
 * byte[] expectedSig = ...; // obtained out-of-band
 *
 * TagEngine&lt;java.security.Signature&gt; eng =
 *     TagEngineBuilder.ed25519Verify(pub).get();
 *
 * // Throw on mismatch at EOF:
 * eng.setVerificationApproach(eng.getVerificationCore().getThrowOnMismatch());
 * eng.setExpectedTag(expectedSig);
 *
 * try (java.io.InputStream in = eng.wrap(bodyWithoutTrailer)) {
 *     in.transferTo(java.io.OutputStream.nullOutputStream());
 * } // VerificationException wrapped in IOException may be raised by the engine at EOF
 * }
 * </pre>
 *
 * <h3>Record verification outcome in a context</h3> <pre>
 * {@code
 * CtxInterface ctx = ...;
 * Key&lt;Boolean&gt; VERIFY_OK = ...;
 *
 * TagEngine&lt;byte[]&gt; eng = TagEngineBuilder.digest(DigestSpec.sha256()).get();
 * eng.setVerificationApproach(eng.getVerificationCore().getFlagOkInCtx(ctx, VERIFY_OK));
 * eng.setExpectedTag(expectedDigest);
 *
 * try (java.io.InputStream in = eng.wrap(bodyWithoutTrailer)) {
 *     in.transferTo(java.io.OutputStream.nullOutputStream());
 * }
 * Boolean ok = ctx.get(VERIFY_OK);
 * }
 * </pre>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Engines are stateful, not thread-safe, and intended for one pipeline run
 * per instance.</li>
 * <li>{@link TagEngine#tagLength()} is fixed for a given engine and is used by
 * higher layers to size or strip trailers when composing pipelines.</li>
 * <li>Verification approaches include constant-time byte comparison
 * ({@link ByteVerificationStrategy}) and JCA-signature-based verification
 * ({@link SignatureVerificationStrategy}). Applications may provide custom
 * strategies.</li>
 * <li>No direct accessor to raw tags is exposed. Engines either append tags
 * (produce mode) or verify them internally (verify mode).</li>
 * </ul>
 *
 * <h2>Builders</h2>
 * <p>
 * {@link TagEngineBuilder} provides factories for common primitives, including
 * digest, HMAC, and signature engines (Ed25519, RSA, ECDSA, SPHINCS+). Each
 * call to {@link TagEngineBuilder#get()} returns a fresh {@link TagEngine}
 * instance.
 * </p>
 *
 * @since 1.0
 */
package zeroecho.core.tag;
