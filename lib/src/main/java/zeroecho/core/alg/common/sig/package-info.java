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
 * Streaming signature contexts and helpers that adapt JCA
 * {@link java.security.Signature} to a pull-based pipeline.
 *
 * <p>
 * This package provides a generic signature context that wraps an
 * {@link java.io.InputStream}, updates a JCA engine as bytes flow, and either
 * appends a fixed-length trailer (sign) or verifies against a caller-supplied
 * tag (verify). A small internal passthrough stream performs byte forwarding
 * and end-of-stream finalization.
 * </p>
 *
 * <h2>Design goals</h2>
 * <ul>
 * <li><b>Single-use pipeline integration:</b> create a context for SIGN or
 * VERIFY and call {@code wrap(InputStream)} once.</li>
 * <li><b>Known tag length up front:</b> produced/expected signature length is
 * resolved at construction so downstream components can append or strip
 * trailers without buffering the whole stream.</li>
 * <li><b>Provider encapsulation:</b> JCA provider details are hidden behind
 * factories that create initialized engines.</li>
 * </ul>
 *
 * <h2>Components</h2>
 * <ul>
 * <li><b>GenericJcaSignatureContext</b> - streaming context that uses a
 * configured {@link java.security.Signature}, resolves a fixed tag length (via
 * resolvers), and exposes a one-shot {@code wrap(InputStream)} API.
 * Verification behavior is controlled by a pluggable comparison approach.</li>
 * <li><b>SignatureStream</b> - internal passthrough input stream that feeds
 * chunks to the signature engine, emits the trailer in SIGN mode, and performs
 * final verification in VERIFY mode.</li>
 * </ul>
 *
 * <h2>Length resolution</h2>
 * <p>
 * Tag length is determined by resolvers supplied at construction time:
 * </p>
 * <ul>
 * <li><b>SignLengthResolver</b> - returns the produced length (fixed or by
 * probing a provider with an empty-message sign).</li>
 * <li><b>VerifyLengthResolver</b> - returns the expected length (fixed or
 * derived from key parameters).</li>
 * </ul>
 *
 * <h2>Verification approach</h2>
 * <p>
 * Verification is delegated to a {@code VerificationBiPredicate} strategy. The
 * default core delegates to {@link java.security.Signature#verify(byte[])}, and
 * callers may decorate it to throw on mismatch or to record results externally.
 * </p>
 *
 * <h2>Usage sketch</h2>
 * <h3>Sign</h3> <pre>
 * {@code
 * GenericJcaSignatureContext ctx = new GenericJcaSignatureContext(
 *     algorithm,
 *     privateKey,
 *     GenericJcaSignatureContext.jcaFactory("SHA256withRSA", null),
 *     GenericJcaSignatureContext.SignLengthResolver.probeWith("SHA256withRSA", null));
 *
 * try (InputStream in = ctx.wrap(upstream)) {
 *     in.transferTo(out); // body, then signature trailer of ctx.tagLength() bytes
 * }
 * }
 * </pre>
 *
 * <h3>Verify</h3> <pre>
 * {@code
 * GenericJcaSignatureContext vctx = new GenericJcaSignatureContext(
 *     algorithm,
 *     publicKey,
 *     GenericJcaSignatureContext.jcaFactory("SHA256withRSA", null),
 *     GenericJcaSignatureContext.VerifyLengthResolver.fixed(256));
 *
 * vctx.setVerificationApproach(vctx.getVerificationCore().getThrowOnMismatch());
 * vctx.setExpectedTag(signatureBytes);
 *
 * try (InputStream verified = vctx.wrap(bodyWithoutTrailer)) {
 *     verified.transferTo(java.io.OutputStream.nullOutputStream()); // throws on mismatch at EOF
 * }
 * }
 * </pre>
 *
 * <h2>Thread-safety</h2>
 * <ul>
 * <li>Contexts and streams are stateful, not thread-safe, and intended for
 * single use.</li>
 * <li>Create a new context per wrapped stream.</li>
 * </ul>
 *
 * @since 1.0
 */
package zeroecho.core.alg.common.sig;
