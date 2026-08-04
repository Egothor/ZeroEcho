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
package zeroecho.pki.server;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiOperationResult;

/** Closed server-control result with explicit one-time-sensitive handling. */
@SuppressWarnings({ "PMD.AvoidLiteralsInIfCondition", "PMD.ControlStatementBraces" })
public sealed interface ServerControlOperationOutcome permits ServerControlOperationOutcome.Ordinary,
        ServerControlOperationOutcome.OneTimeSensitive {
    /** Response handling classification. */
    enum Classification { ORDINARY, ONE_TIME_SENSITIVE }
    /** @return response handling classification */
    Classification classification();

    /** Ordinary safe replayable operation result. */
    record Ordinary(PkiOperationOutcome outcome) implements ServerControlOperationOutcome {
        public Ordinary { Objects.requireNonNull(outcome, "outcome"); }
        @Override public Classification classification() { return Classification.ORDINARY; }
    }

    /** Single-consumption capability delivery result, never a PKI operation value. */
    final class OneTimeSensitive implements ServerControlOperationOutcome {
        private final PkiOperationResult safeResult;
        private final byte[] token;
        private final AtomicBoolean consumed = new AtomicBoolean();

        /** Creates a one-time result after its commitment has been durably persisted. */
        public OneTimeSensitive(PkiOperationResult safeResult, byte[] token) {
            this.safeResult = Objects.requireNonNull(safeResult, "safeResult");
            this.token = Objects.requireNonNull(token, "token").clone();
            if (token.length != 32) throw new IllegalArgumentException("Capability token length is invalid");
        }
        @Override public Classification classification() { return Classification.ONE_TIME_SENSITIVE; }
        /** @return safe non-secret metadata */ public PkiOperationResult safeResult() { return safeResult; }
        /** Consumes the raw token exactly once and clears the retained copy. */
        public byte[] consumeToken() {
            if (!consumed.compareAndSet(false, true)) throw new IllegalStateException("Capability token consumed");
            byte[] result = token.clone();
            Arrays.fill(token, (byte) 0);
            return result;
        }
    }
}
