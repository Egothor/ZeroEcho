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

import java.security.Signature;
import java.security.SignatureException;
import java.util.logging.Level;
import java.util.logging.Logger;

import zeroecho.core.err.VerificationException;
import zeroecho.core.tag.ThrowingBiPredicate.VerificationBiPredicate;
import zeroecho.core.util.Strings;

/**
 * Verification strategy that delegates to a JCA {@link Signature} object.
 *
 * <p>
 * This strategy invokes {@link Signature#verify(byte[])} on the supplied
 * signature instance to validate the given data (typically a detached signature
 * or digest). Logging at {@link Level#FINE} provides pass/fail outcomes using
 * {@link Strings#toShortString(byte[])} for concise output.
 * </p>
 *
 * <p>
 * The wrapped {@link SignatureException} is converted into a
 * {@link VerificationException} to unify error reporting in ZeroEcho
 * verification flows.
 * </p>
 *
 * <p>
 * Example:
 * </p>
 * <pre>
 * {@code
 * Signature jcaSig = Signature.getInstance("Ed25519");
 * jcaSig.initVerify(publicKey);
 * jcaSig.update(message);
 *
 * SignatureVerificationStrategy verifier = new SignatureVerificationStrategy();
 * boolean ok = verifier.verify(jcaSig, detachedSignature);
 * if (!ok) {
 *     // handle verification failure
 * }
 * }
 * </pre>
 */
public class SignatureVerificationStrategy extends VerificationBiPredicate<Signature> {
    private static final Logger LOG = Logger.getLogger(SignatureVerificationStrategy.class.getName());

    /** Creates a stateless JCA signature-verification strategy. */
    public SignatureVerificationStrategy() {
        super();
        // Stateless verifier.
    }

    /**
     * Verifies that the provided {@link Signature} object validates the given
     * bytes.
     *
     * <p>
     * The method calls {@link Signature#verify(byte[])} and logs the outcome at
     * {@link Level#FINE}. If verification fails due to a
     * {@link SignatureException}, the error is wrapped in a
     * {@link VerificationException}.
     * </p>
     *
     * @param s the signature object to use for verification, already initialized
     *          for verification
     * @param b the detached signature or digest to validate against
     * @return {@code true} if verification succeeds, {@code false} otherwise
     * @throws VerificationException if the underlying signature operation fails
     */
    @Override
    public boolean verify(Signature s, byte[] b) throws VerificationException {
        try {
            boolean result = s.verify(b);

            if (LOG.isLoggable(Level.FINE)) {
                if (result) {
                    LOG.log(Level.FINE, "PASS {0}", Strings.toShortString(b));
                } else {
                    LOG.log(Level.FINE, "FAIL {0}", Strings.toShortString(b));
                }
            }

            return result;

        } catch (SignatureException e) {
            throw new VerificationException(e, b);
        }
    }
}
