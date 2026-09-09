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
package zeroecho.pki.api;

import java.util.Objects;

/**
 * Stable typed failure raised by the bounded signing execution runtime.
 *
 * <p>Callers should inspect {@link #classification()} rather than parsing the
 * redacted diagnostic message. Instances never contain signing content or
 * provider diagnostics.</p>
 */
public final class SigningExecutionException extends PkiException {

    private static final long serialVersionUID = -1637260155518829748L;

    /** Small Increment 11 execution failure taxonomy. */
    public enum Classification {
        /** The configured admission population is fully reserved. */
        OVERLOADED,
        /** Admission has stopped because the runtime is shutting down. */
        SHUTTING_DOWN,
        /** A non-cooperative execution step outlived forced shutdown. */
        SHUTDOWN_TIMEOUT
    }

    /** Stable machine-readable execution-failure classification. */
    private final Classification classification;

    /**
     * Creates a stable signing execution failure.
     *
     * @param classification machine-readable failure class
     * @param message safe non-blank diagnostic message
     */
    public SigningExecutionException(Classification classification, String message) {
        super(message);
        this.classification = Objects.requireNonNull(classification, "classification");
    }

    /**
     * Creates a stable signing execution failure with an internal lifecycle cause.
     *
     * @param classification machine-readable failure class
     * @param message safe non-blank diagnostic message
     * @param cause internal cause containing no provider or payload data
     */
    public SigningExecutionException(Classification classification, String message, Throwable cause) {
        super(message, Objects.requireNonNull(cause, "cause"));
        this.classification = Objects.requireNonNull(classification, "classification");
    }

    /**
     * Returns the execution-failure classification.
     *
     * @return stable machine-readable classification
     */
    public Classification classification() {
        return classification;
    }
}
