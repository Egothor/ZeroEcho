/* *****************************************************************************
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
package zeroecho.core.tag;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

import zeroecho.core.alg.common.sig.GenericJcaSignatureContext;
import zeroecho.core.alg.digest.JcaDigestContext;
import zeroecho.core.alg.rsa.RsaSignatureContext;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Minimal streaming engine for producing or verifying authentication tags on
 * byte streams.
 *
 * <p>
 * A {@code TagEngine} adapts stateful primitives (for example
 * {@link java.security.MessageDigest}, {@link java.security.Signature}, or HMAC
 * engines) into a streaming pipeline: a single-use wrapper consumes all bytes
 * from an upstream {@link java.io.InputStream} and, depending on mode, either
 * appends a trailer (produce mode) or verifies a caller-supplied tag (verify
 * mode).
 * </p>
 *
 * <h2>Operation modes</h2>
 * <ul>
 * <li><b>Produce mode</b>: {@link #wrap(InputStream)} returns a passthrough
 * stream. All upstream bytes are emitted unchanged; when end-of-stream is
 * reached, the computed tag is appended as a trailer to the output.</li>
 * <li><b>Verify mode</b>: The caller first supplies the expected tag via
 * {@link #setExpectedTag(byte[])} and ensures the upstream does not include the
 * trailer (for example, by using a tail-stripping wrapper). The returned stream
 * emits only the body. At EOF, the engine compares the computed tag with the
 * expected tag and reports the outcome using the configured verification
 * approach.</li>
 * </ul>
 *
 * <h2>Verification approaches</h2>
 * <p>
 * Verification outcome handling is delegated to a
 * {@link VerificationBiPredicate}. Implementations should provide a sensible
 * default (for example, constant-time equality on byte arrays). Callers may
 * replace or decorate the approach with helpers such as
 * {@link VerificationBiPredicate#getThrowOnMismatch()} or
 * {@link VerificationBiPredicate#getFlagOkInCtx(conflux.CtxInterface, conflux.Key)}.
 * </p>
 *
 * <h2>Implementation notes</h2>
 * <ul>
 * <li>Trailer emission must happen exactly once and only in produce mode. No
 * trailer is ever emitted in verify mode.</li>
 * <li>Engines are stateful and not thread-safe. Each instance is intended for
 * one pipeline run.</li>
 * <li>Typical adapters include:
 * <ul>
 * <li>{@link JcaDigestContext} for SHA-2 and SHA-3 digests</li>
 * <li>{@link GenericJcaSignatureContext} for JCA
 * {@link java.security.Signature}</li>
 * <li>{@link RsaSignatureContext} for RSA-PSS and PKCS#1 signatures</li>
 * </ul>
 * </li>
 * </ul>
 *
 * <p>
 * Direct access to the raw tag is not exposed; engines either append it
 * (produce mode) or check it internally (verify mode).
 * </p>
 *
 * <p>
 * <b>Example:</b>
 * </p>
 * <pre>
 * {@code
 * TagEngine<byte[]> digestEngine = TagEngineBuilder.digest(DigestSpec.sha256()).get();
 * InputStream wrapped = digestEngine.wrap(plaintextIn);
 * // Read all bytes from wrapped; the SHA-256 trailer is appended automatically.
 *
 * TagEngine<java.security.Signature> verifyEngine =
 *         TagEngineBuilder.ed25519Verify(publicKey).get();
 * verifyEngine.setVerificationApproach(
 *         verifyEngine.getVerificationCore().getThrowOnMismatch());
 * verifyEngine.setExpectedTag(expectedTag);
 * InputStream verifyWrapped = verifyEngine.wrap(bodyWithoutTrailer);
 * // Read to EOF; throws on mismatch due to the configured approach.
 * }
 * </pre>
 *
 * @param <T> auxiliary type used by the concrete engine (for example
 *            {@link java.security.Signature} for signature engines or
 *            {@code byte[]} for digest/HMAC engines)
 *
 * @see JcaDigestContext
 * @see GenericJcaSignatureContext
 * @see RsaSignatureContext
 */
public interface TagEngine<T> {
    /** Logger shared by default tag-engine diagnostics. */
    Logger LOG = Logger.getLogger(TagEngine.class.getName());

    /**
     * Wraps the given upstream stream with a filtering stream that both passes
     * bytes through and updates the tag engine state.
     *
     * <p>
     * In produce mode, the wrapper emits the original data followed by the
     * generated tag trailer when EOF is reached. In verify mode, the wrapper
     * validates the expected tag either immediately or at EOF, depending on the
     * engine and the configured verification approach.
     * </p>
     *
     * @param upstream source of plaintext or ciphertext; must not be {@code null}
     * @return a new stream that applies tag computation or verification
     * @throws IOException if wrapping fails or the engine cannot allocate required
     *                     resources
     */
    InputStream wrap(InputStream upstream) throws IOException;

    /**
     * Returns the fixed length in bytes of the final authentication tag.
     *
     * <p>
     * Higher layers use this value to strip or append trailers during stream
     * processing.
     * </p>
     *
     * @return the tag length in bytes
     */
    int tagLength();

    /**
     * Supplies the expected tag for verify mode.
     *
     * <p>
     * Engines may verify immediately if the computed tag is already known, or they
     * may defer verification until EOF. This method is invoked at most once per
     * wrapped stream.
     * </p>
     *
     * <p>
     * The default implementation throws {@link UnsupportedOperationException}.
     * Engines that support verification must override this method.
     * </p>
     *
     * @param expected expected tag value; implementations may defensively copy this
     *                 array
     * @throws UnsupportedOperationException if the engine does not support
     *                                       verification
     */
    default void setExpectedTag(byte[] expected) {
        // default: engines that don't support verify can refuse
        throw new UnsupportedOperationException("Verification not supported by this TagEngine");
    }

    /**
     * Sets the verification approach used to compare computed and expected tags.
     *
     * <p>
     * Typical implementations will default to a constant-time comparison for
     * {@code byte[]} values. Callers may replace or decorate the strategy, for
     * example with {@link VerificationBiPredicate#getThrowOnMismatch()} to raise an
     * exception on mismatch, or
     * {@link VerificationBiPredicate#getFlagOkInCtx(conflux.CtxInterface, conflux.Key)}
     * to record the outcome in a context.
     * </p>
     *
     * @param strategy the verification predicate to use; must not be {@code null}
     */
    void setVerificationApproach(VerificationBiPredicate<T> strategy);

    /**
     * Returns the current verification approach.
     *
     * @return the verification predicate in use; never {@code null} after
     *         initialization
     */
    VerificationBiPredicate<T> getVerificationCore();
}
