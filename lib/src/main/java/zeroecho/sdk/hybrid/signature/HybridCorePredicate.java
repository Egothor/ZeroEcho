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
package zeroecho.sdk.hybrid.signature;

import java.security.Signature;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.err.VerificationException;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;

/**
 * Hybrid verification core predicate delegating the final decision to the
 * hybrid engine's end-of-stream (EOF) aggregation.
 *
 * <p>
 * This predicate does not perform any cryptographic verification on its own.
 * Instead, it acts as a bridge between the generic verification pipeline and
 * the hybrid streaming engine, where the actual verification of classic and PQC
 * signatures is performed once the complete payload has been consumed.
 * </p>
 *
 * <p>
 * The boolean result returned by {@link #verify(Signature, byte[])} reflects
 * the outcome computed during EOF processing and stored in the shared
 * {@link AtomicBoolean} instance. This allows the verification decision to be
 * made exactly once, based on the fully buffered message body and the hybrid
 * verification rule.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>The {@code signature} and {@code expectedTag} parameters are
 * intentionally ignored, as the hybrid model defers verification until all data
 * has been read from the stream.</li>
 * <li>This class is immutable and thread-safe with respect to its own state;
 * however, correctness depends on coordinated usage with the associated hybrid
 * stream.</li>
 * <li>The predicate must be used only in conjunction with a hybrid signature
 * stream that updates the shared {@code lastOk} flag.</li>
 * </ul>
 *
 * <p>
 * Security note: this predicate must not leak any sensitive material. It merely
 * returns a boolean decision computed elsewhere and does not inspect keys,
 * signatures, or plaintext data.
 * </p>
 *
 * @since 1.0
 */
final class HybridCorePredicate extends VerificationBiPredicate<Signature> {
    private static final Logger LOGGER = Logger.getLogger(HybridCorePredicate.class.getName());

    /**
     * Holds the final hybrid verification result computed at end-of-stream.
     */
    private final AtomicBoolean lastOk;

    /**
     * Creates a new hybrid core predicate bound to the given verification result
     * flag.
     *
     * @param lastOk shared atomic flag holding the final hybrid verification result
     * @throws NullPointerException if {@code lastOk} is {@code null}
     */
    protected HybridCorePredicate(AtomicBoolean lastOk) {
        super();
        this.lastOk = Objects.requireNonNull(lastOk, "lastOk");
    }

    /**
     * Returns the hybrid verification result computed during EOF processing.
     *
     * <p>
     * This method performs no validation of the provided {@code signature} or
     * {@code expectedTag}. All cryptographic checks have already been executed by
     * the hybrid stream once the complete payload was available.
     * </p>
     *
     * @param signature   ignored; present to satisfy the predicate contract
     * @param expectedTag ignored; present to satisfy the predicate contract
     * @return {@code true} if the hybrid verification succeeded according to the
     *         configured hybrid verification rule, {@code false} otherwise
     * @throws VerificationException never thrown by this implementation, but
     *                               declared to satisfy the overridden contract
     */
    @Override
    public boolean verify(Signature signature, byte[] expectedTag) throws VerificationException {
        boolean result = lastOk.get();

        if (LOGGER.isLoggable(Level.FINE)) {
            LOGGER.log(Level.FINE, "Hybrid core verification result={0}", result);
        }

        return result;
    }
}
