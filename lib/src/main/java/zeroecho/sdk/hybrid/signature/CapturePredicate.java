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
package zeroecho.sdk.hybrid.signature;

import java.security.Signature;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.err.VerificationException;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Verification predicate wrapper that captures the boolean verification result
 * and never propagates {@link VerificationException} to its caller.
 *
 * <p>
 * This wrapper delegates verification to a supplied
 * {@link VerificationBiPredicate} and records the boolean outcome into a shared
 * {@link AtomicBoolean}. If the delegate throws {@link VerificationException},
 * the exception is suppressed and the verification is treated as a failure
 * (returns {@code false}).
 * </p>
 *
 * <p>
 * This behavior is required for robust hybrid verification semantics, most
 * notably for logical OR composition: individual component verifiers may throw
 * on malformed or structurally invalid signatures (for example, certain Ed25519
 * invalid point encodings). Translating such exceptions into a boolean failure
 * allows the hybrid engine to continue evaluating alternative verification
 * paths and to aggregate the final decision deterministically.
 * </p>
 *
 * <h2>Logging</h2>
 * <p>
 * For diagnostic purposes, a {@link Level#FINE} log entry is emitted on each
 * invocation containing:
 * </p>
 * <ul>
 * <li>a short hexadecimal prefix of {@code expectedTag} (bounded and
 * truncated), and</li>
 * <li>the resulting verification decision ({@code true}/{@code false}).</li>
 * </ul>
 *
 * <p>
 * The logged tag prefix is intentionally truncated to reduce the risk of
 * leaking sensitive material. The log message is produced using a JUL
 * formatting string (no string concatenation in the hot path) and is only
 * constructed when {@code FINE} is enabled.
 * </p>
 *
 * <h2>Threading and side effects</h2>
 * <ul>
 * <li>This class is immutable with respect to its own fields.</li>
 * <li>The {@code ok} flag is updated exactly once per invocation with the
 * result returned by this method (including failures caused by suppressed
 * exceptions).</li>
 * <li>Correctness depends on coordinated usage of the shared
 * {@link AtomicBoolean} when used concurrently.</li>
 * </ul>
 *
 * <p>
 * Security note: this class must not log keys, plaintext, shared secrets, full
 * tags, or other sensitive material. Only a bounded prefix is logged at
 * {@code FINE} level.
 * </p>
 *
 * @since 1.0
 */
final class CapturePredicate extends VerificationBiPredicate<Signature> {

    private static final Logger LOGGER = Logger.getLogger(CapturePredicate.class.getName());

    /**
     * Maximum number of bytes from {@code expectedTag} included in log output.
     */
    private static final int TAG_LOG_PREFIX_BYTES = 8;

    /**
     * Underlying verification predicate performing the actual cryptographic check.
     */
    private final VerificationBiPredicate<Signature> delegate;

    /**
     * Shared atomic flag capturing the result of the most recent verification.
     */
    private final AtomicBoolean ok;

    /**
     * Creates a new capturing predicate.
     *
     * @param delegate the underlying verification predicate to invoke
     * @param ok       shared atomic flag receiving the verification outcome
     * @throws NullPointerException if {@code delegate} or {@code ok} is
     *                              {@code null}
     */
    protected CapturePredicate(VerificationBiPredicate<Signature> delegate, AtomicBoolean ok) {
        super();
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.ok = Objects.requireNonNull(ok, "ok");
    }

    /**
     * Invokes the delegate predicate, captures its boolean result, and never
     * propagates {@link VerificationException}.
     *
     * <p>
     * If the delegate completes normally, its return value is recorded into
     * {@link #ok} and returned. If the delegate throws
     * {@link VerificationException}, the exception is suppressed, {@code false} is
     * recorded into {@link #ok}, and {@code false} is returned.
     * </p>
     *
     * <p>
     * A {@link Level#FINE} log entry is emitted with a truncated hexadecimal prefix
     * of {@code expectedTag} and the resulting decision.
     * </p>
     *
     * @param signature   the signature object to verify
     * @param expectedTag the expected signature tag (may be {@code null}, in which
     *                    case {@code "<null>"} is logged)
     * @return {@code true} if verification succeeded, {@code false} otherwise
     * @throws VerificationException never thrown by this implementation, but
     *                               declared to satisfy the overridden contract
     */
    @Override
    public boolean verify(Signature signature, byte[] expectedTag) throws VerificationException {
        boolean result;
        try {
            result = delegate.verify(signature, expectedTag);
        } catch (VerificationException ex) {
            result = false;
        }

        ok.set(result);

        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.log(Level.FINE, "Hybrid verify: expectedTagPrefix={0}, result={1}",
                    new Object[] { formatTagPrefix(expectedTag), result });
        }

        return result;
    }

    /**
     * Formats a short hexadecimal prefix of the provided tag for logging.
     *
     * <p>
     * At most {@link #TAG_LOG_PREFIX_BYTES} bytes are included. If the tag is
     * longer, the output is suffixed with {@code "..."}.
     * </p>
     *
     * <p>
     * The output format uses lowercase hexadecimal digits without separators.
     * </p>
     *
     * @param tag tag bytes to format (may be {@code null})
     * @return a bounded, log-safe hexadecimal prefix, or {@code "<null>"} if
     *         {@code tag} is {@code null}
     */
    private static String formatTagPrefix(byte[] tag) {
        if (tag == null) {
            return "<null>";
        }

        int n = Math.min(tag.length, TAG_LOG_PREFIX_BYTES);
        StringBuilder sb = new StringBuilder(n * 2 + 3);

        for (int i = 0; i < n; i++) {
            sb.append(Character.forDigit((tag[i] >>> 4) & 0x0f, 16)).append(Character.forDigit(tag[i] & 0x0f, 16));
        }

        if (tag.length > n) {
            sb.append("...");
        }

        return sb.toString();
    }
}
