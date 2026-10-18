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
package zeroecho.pki.server.ct;

/**
 * Thrown when pre-certificate submission to a CT log fails.
 *
 * <p>Failures include: network errors, HTTP 4xx/5xx responses after all retries
 * are exhausted, deadline expiry, and response parsing failures. The {@link #logId()}
 * identifies which CT log caused the failure so callers can decide whether to
 * fall back to other configured logs.</p>
 *
 * @since 1.0
 */
public final class CtSubmissionException extends Exception {

    /** Serialization identity for this exception type. */
    private static final long serialVersionUID = 1L;

    /** Identifier of the log whose submission failed. */
    private final String logId;

    /**
     * Creates an exception for the given CT log.
     *
     * @param message human-readable failure description; must not be {@code null}
     * @param logId   hex log ID of the CT log that failed; must not be {@code null}
     */
    public CtSubmissionException(final String message, final String logId) {
        super(message);
        this.logId = logId;
    }

    /**
     * Creates an exception wrapping a lower-level cause.
     *
     * @param message human-readable failure description; must not be {@code null}
     * @param logId   hex log ID of the CT log that failed; must not be {@code null}
     * @param cause   lower-level exception that triggered this failure; may be {@code null}
     */
    public CtSubmissionException(final String message, final String logId, final Throwable cause) {
        super(message, cause);
        this.logId = logId;
    }

    /**
     * Returns the hex log ID of the CT log that failed.
     *
     * @return hex log ID
     */
    public String logId() {
        return logId;
    }
}
