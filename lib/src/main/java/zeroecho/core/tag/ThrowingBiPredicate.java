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
package zeroecho.core.tag;

import java.util.Objects;

import conflux.CtxInterface;
import conflux.Key;
import zeroecho.core.err.VerificationException;

/**
 * A functional predicate of two arguments that may throw a checked exception.
 *
 * <p>
 * This contract mirrors {@code java.util.function.BiPredicate} but allows the
 * {@link #verify(Object, Object)} method to throw a checked exception. It is
 * intended for verification and comparison routines that may fail due to
 * validation or cryptographic errors, while still enabling use in lambda
 * expressions and method references.
 * </p>
 *
 * <p>
 * Example:
 * </p>
 * <pre>
 * {@code
 * ThrowingBiPredicate<byte[], byte[], VerificationException> constantTimeEq =
 *         new ByteVerificationStrategy()::verify;
 *
 * boolean ok = constantTimeEq.verify(actualSignature, expectedSignature);
 * }
 * </pre>
 *
 * @param <T> the type of the first input to the predicate
 * @param <U> the type of the second input to the predicate
 * @param <E> the type of exception that may be thrown
 */
@FunctionalInterface
public interface ThrowingBiPredicate<T, U, E extends Exception> {
    /**
     * Evaluates this predicate on the given arguments.
     *
     * @param t the first input value
     * @param u the second input value
     * @return {@code true} if the predicate holds for the supplied values;
     *         {@code false} otherwise
     * @throws E if evaluation fails and the implementation chooses to signal the
     *           failure via an exception
     */
    boolean verify(T t, U u) throws E;

    /**
     * Base type for verification strategies that compare a value of type {@code T}
     * to a byte array and may throw {@link VerificationException}.
     *
     * <p>
     * Implementations define the {@link #verify(Object, byte[])} method to perform
     * the actual check (for example, constant-time byte comparison). This base type
     * also provides adapters to compose behavior, such as throwing on mismatch or
     * recording the result in an execution context.
     * </p>
     *
     * <p>
     * Example:
     * </p>
     * <pre>
     * {@code
     * VerificationBiPredicate<byte[]> verifier = new ByteVerificationStrategy();
     * boolean ok = verifier.verify(actual, expected);
     *
     * // Decorate to throw an exception when verification fails:
     * verifier.getThrowOnMismatch().verify(actual, expected);
     * }
     * </pre>
     *
     * @param <T> the type of the first value being verified
     */
    abstract class VerificationBiPredicate<T> implements ThrowingBiPredicate<T, byte[], VerificationException> {
        /**
         * Verifies that {@code t} matches {@code u} according to the implementation
         * contract.
         *
         * @param t the first value to verify
         * @param u the byte array to verify against
         * @return {@code true} if the values are considered a match; {@code false}
         *         otherwise
         * @throws VerificationException if verification cannot be completed or must be
         *                               signaled as an error
         */
        @Override
        public abstract boolean verify(T t, byte[] u) throws VerificationException;

        /**
         * Returns a decorator that throws {@link VerificationException} if verification
         * fails.
         *
         * <p>
         * The returned predicate delegates to this instance. When the delegated
         * verification returns {@code false}, the decorator throws a
         * {@link VerificationException} carrying the most relevant values for
         * diagnostics.
         * </p>
         *
         * <p>
         * Example:
         * </p>
         * <pre>
         * {@code
         * VerificationBiPredicate<byte[]> mustMatch =
         *         new ByteVerificationStrategy().getThrowOnMismatch();
         *
         * // Will throw VerificationException if arrays do not match
         * mustMatch.verify(actual, expected);
         * }
         * </pre>
         *
         * @return a verification predicate that throws on mismatch
         */
        public VerificationBiPredicate<T> getThrowOnMismatch() {
            return new ThrowOnMismatch<>(this);
        }

        /**
         * Returns a decorator that records the verification outcome into the supplied
         * context.
         *
         * <p>
         * The returned predicate delegates to this instance, stores the boolean result
         * under {@code verifyKey} in {@code ctx}, and then returns that result. This is
         * useful when callers need to access the outcome outside the immediate call
         * path.
         * </p>
         *
         * <p>
         * Example:
         * </p>
         * <pre>
         * {@code
         * VerificationBiPredicate<byte[]> withFlag =
         *         new ByteVerificationStrategy().getFlagOkInCtx(ctx, VERIFY_KEY);
         *
         * boolean ok = withFlag.verify(actual, expected);
         * // Later: ctx.get(VERIFY_KEY) yields the same boolean
         * }
         * </pre>
         *
         * @param ctx       the context into which the result is stored; must not be
         *                  {@code null}
         * @param verifyKey the key under which the boolean result is stored; must not
         *                  be {@code null}
         * @return a verification predicate that records the outcome in the provided
         *         context
         */
        public VerificationBiPredicate<T> getFlagOkInCtx(CtxInterface ctx, Key<Boolean> verifyKey) {
            return new FlagOkInCtx<>(this, ctx, verifyKey);
        }
    }

    /**
     * Decorator that throws {@link VerificationException} when the delegated
     * verification fails.
     *
     * <p>
     * If the value {@code t} being verified is a {@code byte[]} instance, the
     * thrown exception includes both the expected and calculated arrays for clearer
     * diagnostics. Otherwise the exception includes the byte array argument.
     * </p>
     *
     * @param <T> the type of the first value being verified
     */
    final class ThrowOnMismatch<T> extends VerificationBiPredicate<T> {
        /**
         * The underlying verification strategy to delegate to.
         */
        private final VerificationBiPredicate<T> delegate;

        /**
         * Creates a new throwing decorator.
         *
         * @param delegate the underlying verifier to call; must not be {@code null}
         */
        public ThrowOnMismatch(VerificationBiPredicate<T> delegate) {
            super();

            this.delegate = Objects.requireNonNull(delegate);
        }

        /**
         * Verifies that {@code t} matches {@code u}; throws on mismatch.
         *
         * @param t the first value to verify
         * @param u the byte array to verify against
         * @return {@code true} if the values match
         * @throws VerificationException if the values do not match, or if the delegate
         *                               throws
         */
        @Override
        public boolean verify(T t, byte[] u) throws VerificationException {
            boolean equality = delegate.verify(t, u);

            if (!equality) {
                if (t instanceof byte[] array) {
                    throw new VerificationException(array, u);
                } else {
                    throw new VerificationException(u);
                }
            }
            return equality;
        }

    }

    /**
     * Decorator that records the verification outcome in a context before returning
     * it.
     *
     * <p>
     * The result of {@link #verify(Object, byte[])} is stored under the provided
     * {@code verifyKey} in {@code ctx}. The recorded value is {@code true} for a
     * successful verification and {@code false} otherwise.
     * </p>
     *
     * @param <T> the type of the first value being verified
     */
    final class FlagOkInCtx<T> extends VerificationBiPredicate<T> {
        /**
         * The underlying verification strategy to delegate to.
         */
        private final VerificationBiPredicate<T> delegate;
        /**
         * The context that will receive the verification outcome.
         */
        private final CtxInterface ctx;
        /**
         * The key under which the boolean verification outcome is stored.
         */
        private final Key<Boolean> verifyKey;

        /**
         * Creates a new context-flagging decorator.
         *
         * @param delegate  the underlying verifier to call; must not be {@code null}
         * @param ctx       the context that will store the boolean outcome; must not be
         *                  {@code null}
         * @param verifyKey the key under which the outcome is recorded; must not be
         *                  {@code null}
         */
        public FlagOkInCtx(VerificationBiPredicate<T> delegate, CtxInterface ctx, Key<Boolean> verifyKey) {
            super();

            this.delegate = Objects.requireNonNull(delegate);
            this.ctx = Objects.requireNonNull(ctx, "context cannot be null");
            this.verifyKey = Objects.requireNonNull(verifyKey, "verification-key cannot be null");
        }

        /**
         * Verifies that {@code s} matches {@code b}, records the outcome, and returns
         * it.
         *
         * @param s the first value to verify
         * @param b the byte array to verify against
         * @return {@code true} if the values match; {@code false} otherwise
         * @throws VerificationException if the delegate throws during verification
         */
        @Override
        public boolean verify(T s, byte[] b) throws VerificationException {
            boolean equality = delegate.verify(s, b);

            ctx.put(verifyKey, equality);

            return equality;
        }
    }
}
