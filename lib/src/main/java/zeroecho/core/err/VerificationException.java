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
package zeroecho.core.err;

import java.security.SignatureException;


/**
 * Exception thrown when a cryptographic signature or digest verification fails.
 * 
 * <p>
 * This exception may carry the calculated value, and optionally the expected
 * value, to aid in debugging and error reporting. In case of failures
 * originating from lower-level signature APIs, the original
 * {@link java.security.SignatureException} may be wrapped as the cause.
 * </p>
 */
public class VerificationException extends Exception {
    private static final long serialVersionUID = 7226636637976744245L;
    /**
     * The calculated value that failed verification, typically a signature or
     * digest.
     */
    private final byte[] a;
    /**
     * The expected value to be compared against, or {@code null} if not provided.
     */
    private final byte[] expected;

    /**
     * Creates a new exception with only the calculated value.
     * 
     * <p>
     * This form is typically used when there is no known expected value, but the
     * calculated value is still useful for diagnostics.
     * </p>
     * 
     * @param a the calculated value, may be {@code null}. A defensive copy is made.
     */
    public VerificationException(byte[] a) {
        super();

        this.a = (a == null) ? null : a.clone();
        this.expected = null;
    }

    /**
     * Creates a new exception with both expected and calculated values.
     * 
     * <p>
     * This form is useful when the verification mismatch can be expressed in terms
     * of what was expected versus what was actually obtained.
     * </p>
     * 
     * @param expected the expected value, may be {@code null}. A defensive copy is
     *                 made.
     * @param a        the calculated value, may be {@code null}. A defensive copy
     *                 is made.
     */
    public VerificationException(byte[] expected, byte[] a) {
        super();

        this.a = (a == null) ? null : a.clone();
        this.expected = (expected == null) ? null : expected.clone();
    }

    /**
     * Creates a new exception that wraps a lower-level
     * {@link java.security.SignatureException}.
     * 
     * <p>
     * This form allows the original exception to be preserved while attaching the
     * calculated value that caused the failure.
     * </p>
     * 
     * @param e the original signature exception to wrap, must not be {@code null}
     * @param a the calculated value, may be {@code null}. A defensive copy is made.
     */
    public VerificationException(SignatureException e, byte[] a) {
        super(e);

        this.a = (a == null) ? null : a.clone();
        this.expected = null;
    }

    /**
     * Returns a string representation of this exception.
     * 
     * <p>
     * The returned string includes both expected and calculated values if
     * available, or the message of the wrapped cause if present.
     * </p>
     * 
     * @return a descriptive string representation of the exception
     */
    @Override
    public String toString() {
        // Lengths only — not raw bytes — to avoid signature material in audit logs.
        int aLen = a != null ? a.length : -1;
        return expected != null
                ? "VerificationException: invalid signature, expected.length=" + expected.length
                        + " but calculated.length=" + aLen
                : getCause() == null ? "VerificationException: invalid signature length=" + aLen
                        : "VerificationException: " + getCause().getMessage() + " length=" + aLen;
    }

}
