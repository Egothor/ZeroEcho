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
package zeroecho.pki.cli;

import java.util.Objects;

import zeroecho.core.io.CancellationSignal;
import java.util.Optional;
import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.signing.SigningAcceptanceReceipt;
import zeroecho.pki.application.LocalSigningExecutor;
import zeroecho.pki.application.LocalSigningResult;
import zeroecho.pki.application.PkiOperationFailure;
import zeroecho.pki.application.PkiOperationOutcome;
import zeroecho.pki.application.PkiSession;

/**
 * In-process {@link PkiOperationTransport} that executes operations against a
 * lifecycle-owned {@link PkiSession}.
 *
 * <p>The session is owned by the composition root ({@code PkiCli}), which is
 * responsible for closing it after rendering; this adapter therefore borrows the
 * session and never closes it.</p>
 */
final class LocalPkiOperationTransport implements PkiOperationTransport {

    private final PkiSession session;

    /**
     * Creates a transport over one already-opened session.
     *
     * @param session lifecycle-owned backend session
     */
    /* default */ LocalPkiOperationTransport(PkiSession session) {
        this.session = Objects.requireNonNull(session, "session");
    }

    @Override
    public PkiLocalResult execute(PkiLocalCommand command, CancellationSignal cancellation) {
        if (command instanceof PkiLocalCommand.Core core) {
            PkiOperationOutcome outcome = session.operations().execute(core.operation(), cancellation);
            return new PkiLocalResult(outcome, outcome instanceof PkiOperationOutcome.Pending pending
                    ? Optional.of(pending.operationId()) : Optional.empty());
        }
        Optional<PkiId> requested = switch (command) {
            case PkiLocalCommand.Inspect inspect -> Optional.of(inspect.operationId());
            case PkiLocalCommand.Complete complete -> Optional.of(complete.operationId());
            default -> Optional.empty();
        };
        String name = switch (command) {
            case PkiLocalCommand.Signing signing -> signing.operation().name();
            case PkiLocalCommand.Inspect ignored -> PkiLocalCommand.INSPECT;
            case PkiLocalCommand.Complete ignored -> PkiLocalCommand.COMPLETE;
            default -> throw new IllegalArgumentException("Unsupported local command");
        };
        Optional<LocalSigningExecutor> executor = session.localSigning();
        if (executor.isEmpty()) {
            return new PkiLocalResult(new PkiOperationOutcome.Failed(name,
                    PkiOperationFailure.VALIDATION_FAILURE, "CAPABILITY_NOT_CONFIGURED"), requested);
        }
        if (command instanceof PkiLocalCommand.Inspect inspect) {
            return new PkiLocalResult(executor.orElseThrow().inspect(inspect.operationId(), cancellation), requested);
        }
        LocalSigningResult result = command instanceof PkiLocalCommand.Signing signing
                ? executor.orElseThrow().execute(signing.operation(), cancellation)
                : executor.orElseThrow().complete(((PkiLocalCommand.Complete) command).operationId(), cancellation);
        if (result instanceof LocalSigningResult.Completed completed) {
            return new PkiLocalResult(new PkiOperationOutcome.Completed(completed.result()),
                    Optional.of(completed.receipt().operationId()));
        }
        LocalSigningResult.Failed failed = (LocalSigningResult.Failed) result;
        return new PkiLocalResult(failed.failure(), failed.receipt().map(
                SigningAcceptanceReceipt::operationId).or(() -> requested));
    }
}
