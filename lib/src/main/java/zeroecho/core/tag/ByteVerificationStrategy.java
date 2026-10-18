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

import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.err.VerificationException;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;
import zeroecho.core.util.Strings;

/**
 * Verification strategy for comparing two byte arrays in constant time.
 * 
 * <p>
 * This implementation is intended for cryptographic use cases such as verifying
 * signatures, digests, or message authentication codes. The comparison runs in
 * constant time with respect to the contents of the arrays, in order to avoid
 * timing side-channel leaks that might otherwise reveal partial information.
 * </p>
 * 
 * <p>
 * Logging at {@link Level#FINE} is available to report pass or fail outcomes
 * with truncated array contents using {@link Strings#toShortString(byte[])}.
 * </p>
 */
public class ByteVerificationStrategy extends VerificationBiPredicate<byte[]> {
    private static final Logger LOG = Logger.getLogger(ByteVerificationStrategy.class.getName());

    /**
     * Creates a stateless constant-time byte-array verifier.
     */
    public ByteVerificationStrategy() {
        super();
        // Stateless verifier.
    }

    /**
     * Verifies that two byte arrays are equal using a constant-time comparison.
     * 
     * <p>
     * The method compares the arrays byte by byte, accumulating differences without
     * early exit. This ensures the runtime depends only on the length of the arrays
     * and not on their contents, which is critical in cryptographic contexts. If
     * the arrays differ in length or either is {@code null}, the result is
     * {@code false}.
     * </p>
     * 
     * <p>
     * Example:
     * </p>
     * 
     * <pre>
     * {@code
     * ByteVerificationStrategy verifier = new ByteVerificationStrategy();
     * boolean ok = verifier.verify(signature1, signature2);
     * if (!ok) {
     *     throw new VerificationException(signature2, signature1);
     * }
     * }
     * </pre>
     * 
     * @param a the first byte array to compare, may be {@code null}
     * @param b the second byte array to compare, may be {@code null}
     * @return {@code true} if both arrays are non-null, of the same length, and
     *         have identical contents; {@code false} otherwise
     * @throws VerificationException if the comparison process itself fails (not
     *                               typically expected in this implementation)
     */
    @Override
    public boolean verify(byte[] a, byte[] b) throws VerificationException {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int r = 0;
        for (int i = 0; i < a.length; i++) {
            r |= (a[i] ^ b[i]);
        }

        if (LOG.isLoggable(Level.FINE)) {
            if (r == 0) {
                LOG.log(Level.FINE, "PASS {0} == {1}",
                        new Object[] { Strings.toShortString(a), Strings.toShortString(b) });
            } else {
                LOG.log(Level.FINE, "FAIL {0} != {1}",
                        new Object[] { Strings.toShortString(a), Strings.toShortString(b) });
            }
        }

        return r == 0;
    }
}
