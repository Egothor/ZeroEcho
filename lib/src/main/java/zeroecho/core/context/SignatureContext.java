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

import java.security.Signature;

import zeroecho.core.tag.TagEngine;
import zeroecho.core.tag.ThrowingBiPredicate;

/**
 * Context for streaming digital signature operations in pull-based pipelines.
 *
 * <p>
 * A {@code SignatureContext} encapsulates the state of a signature algorithm
 * such as Ed25519, ECDSA, or RSA-PSS and exposes it through the
 * {@link TagEngine} contract. In produce (SIGN) mode it consumes the message
 * bytes and appends the computed signature as a trailer; in verify (VERIFY)
 * mode it consumes the message bytes and checks an expected signature supplied
 * by the caller.
 * </p>
 *
 * <h2>Operation</h2>
 * <ul>
 * <li><b>Produce mode:</b> {@link TagEngine#wrap(java.io.InputStream)} returns
 * a passthrough stream that emits the original data and, at end-of-stream,
 * appends the signature trailer.</li>
 * <li><b>Verify mode:</b> Provide the expected signature with
 * {@link TagEngine#setExpectedTag(byte[])} and ensure the upstream body does
 * not include a trailer. At end-of-stream the computed signature is compared
 * against the expected one using the configured verification approach set via
 * {@link TagEngine#setVerificationApproach(ThrowingBiPredicate.VerificationBiPredicate)}.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <h3>Sign with Ed25519</h3> <pre>
 * {@code
 * TagEngine<java.security.Signature> eng =
 *     TagEngineBuilder.ed25519Sign(privateKey).get();
 *
 * try (java.io.InputStream in = eng.wrap(upstream)) {
 *     in.transferTo(out); // body, then detached signature trailer
 * }
 * }
 * </pre>
 *
 * <h3>Verify a detached signature and throw on mismatch</h3> <pre>
 * {@code
 * byte[] expectedSig = ...; // obtained via a trusted channel
 * TagEngine<java.security.Signature> eng =
 *     TagEngineBuilder.ed25519Verify(publicKey).get();
 *
 * // Throw if verification fails at EOF:
 * eng.setVerificationApproach(eng.getVerificationCore().getThrowOnMismatch());
 * eng.setExpectedTag(expectedSig);
 *
 * try (java.io.InputStream in = eng.wrap(bodyWithoutTrailer)) {
 *     in.transferTo(java.io.OutputStream.nullOutputStream()); // compare at EOF
 * }
 * }
 * </pre>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>Instances bind to a specific key and are single-use; they are not
 * thread-safe.</li>
 * <li>The signature length reported by {@link TagEngine#tagLength()} is
 * algorithm specific and can be used by higher layers to handle trailers.</li>
 * <li>Verification failures are handled by the configured approach, for example
 * {@link ThrowingBiPredicate.VerificationBiPredicate#getThrowOnMismatch()} or
 * {@link ThrowingBiPredicate.VerificationBiPredicate#getFlagOkInCtx(conflux.CtxInterface, conflux.Key)}.</li>
 * </ul>
 *
 * @since 1.0
 */
public non-sealed interface SignatureContext extends TagEngine<Signature>, CryptoContext {
}
