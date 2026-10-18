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
package zeroecho.pki.api;

import java.io.Serial;
import java.util.Objects;

/**
 * PKI exception carrying a stable, non-sensitive failure description.
 *
 * <p>
 * The direct exception message and inherited {@link #toString()} representation
 * are derived exclusively from {@link PkiFailure#classification()} and
 * {@link PkiFailure#code()}; they do not incorporate the message or textual
 * representation of an underlying cause.
 * </p>
 *
 * <p>
 * The complete {@link Throwable} graph is trusted-process-only. Its cause,
 * suppressed exceptions, and stack trace can contain sensitive provider text,
 * hostile input, filesystem details, or application internals. Consequently,
 * this exception must not be exported, serialized, or logged across a diagnostic
 * trust boundary. Only the detached value returned by {@link #failure()} is safe
 * to carry across such a boundary.
 * </p>
 *
 * <p>
 * Construction and access require constant time and auxiliary memory because
 * {@link PkiFailure} contains only closed-enum components.
 * </p>
 */
public final class PkiFailureException extends PkiException {

    @Serial
    private static final long serialVersionUID = -7214558134284529884L;

    /** Detached non-sensitive failure description. */
    private final PkiFailure failure;

    /**
     * Creates an exception for a validated PKI failure.
     *
     * @param failure non-sensitive failure description
     * @throws NullPointerException if {@code failure} is {@code null}
     */
    public PkiFailureException(PkiFailure failure) {
        super(message(failure));
        this.failure = failure;
    }

    /**
     * Creates an exception for a validated PKI failure with an internal cause.
     *
     * <p>The cause is retained by identity but its text is not included in the
     * direct exception message or string representation. The exception and its
     * throwable graph remain trusted-process-only.</p>
     *
     * @param failure non-sensitive failure description
     * @param cause non-null underlying cause retained for trusted diagnostics
     * @throws NullPointerException if {@code failure} or {@code cause} is {@code null}
     */
    public PkiFailureException(PkiFailure failure, Throwable cause) {
        super(message(failure), Objects.requireNonNull(cause, "cause"));
        this.failure = failure;
    }

    /**
     * Returns the stable failure description.
     *
     * @return immutable non-sensitive failure description
     */
    public PkiFailure failure() {
        return failure;
    }

    private static String message(PkiFailure failure) {
        PkiFailure checkedFailure = Objects.requireNonNull(failure, "failure");
        return "PKI failure: classification=" + checkedFailure.classification()
                + ", code=" + checkedFailure.code().name();
    }
}
