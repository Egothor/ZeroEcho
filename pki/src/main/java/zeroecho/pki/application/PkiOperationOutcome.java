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
package zeroecho.pki.application;

import java.util.Objects;

/** Closed completed, durable-pending, or safe-failure outcome returned by the operation executor. */
public sealed interface PkiOperationOutcome permits PkiOperationOutcome.Completed,
        PkiOperationOutcome.Pending, PkiOperationOutcome.Failed {

    /**
     * Successful operation outcome.
     *
     * @param result safe transport-neutral result
     */
    record Completed(PkiOperationResult result) implements PkiOperationOutcome {
        /** Validates the result. */
        public Completed {
            Objects.requireNonNull(result, "result");
        }
    }

    /**
     * Durable operation that yielded without retaining its caller thread.
     *
     * @param operationName stable semantic operation name
     * @param operationId private durable identifier
     */
    record Pending(String operationName, zeroecho.pki.api.PkiId operationId) implements PkiOperationOutcome {
        /** Validates the stable operation and durable private identifier. */
        public Pending {
            if (operationName == null || operationName.isBlank()) {
                throw new IllegalArgumentException("operationName must not be blank");
            }
            Objects.requireNonNull(operationId, "operationId");
        }
    }

    /**
     * Safely classified operation failure without a throwable graph.
     *
     * @param operationName stable semantic name
     * @param classification closed failure class
     * @param code stable non-sensitive code
     */
    record Failed(String operationName, PkiOperationFailure classification, String code)
            implements PkiOperationOutcome {
        /** Validates stable, non-sensitive failure data. */
        public Failed {
            if (operationName == null || operationName.isBlank() || code == null || !code.matches("[A-Z0-9_]{3,64}")) {
                throw new IllegalArgumentException("Operation failure identity or code is invalid");
            }
            Objects.requireNonNull(classification, "classification");
        }
    }
}
