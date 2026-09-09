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
package zeroecho.pki.cli;

/**
 * Maps a remote admin-API {@link PkiRemoteResult} to the same stable process
 * exit codes the local backend uses, so a caller cannot observe a difference in
 * exit semantics between local and remote execution.
 *
 * <p>The server failure classification strings mirror the local
 * {@code PkiOperationFailure} taxonomy, plus the transport-level classifications
 * {@code AUTHORIZATION_DENIED} and {@code DEADLINE_EXCEEDED}. The mapping is:</p>
 *
 * <ul>
 *   <li>{@code VALIDATION_FAILURE}, {@code POLICY_REJECTION},
 *       {@code AUTHORIZATION_DENIED} &rarr; {@code 4}</li>
 *   <li>{@code NOT_FOUND}, {@code CONFLICT} &rarr; {@code 5}</li>
 *   <li>{@code RECOVERY_REQUIRED} &rarr; {@code 6}</li>
 *   <li>{@code EXTERNAL_OUTCOME_UNKNOWN}, {@code DEADLINE_EXCEEDED} &rarr;
 *       {@code 7}</li>
 *   <li>{@code RESOURCE_FAILURE}, {@code OVERLOADED} &rarr; {@code 8}</li>
 *   <li>{@code CANCELLED} &rarr; {@code 130}</li>
 *   <li>{@code INTERNAL_FAILURE} and any unrecognized classification &rarr;
 *       {@code 9}</li>
 * </ul>
 *
 * <p>An {@code APPROVAL_REQUIRED} outcome exits {@code 4}
 * ({@code VALIDATION_OR_POLICY}); a {@code PENDING} outcome that outlasted the
 * bounded wait exits {@code 7} ({@code EXTERNAL_OUTCOME_UNKNOWN}) so the operator
 * can resume it, exactly as the local bounded-wait path does.</p>
 */
final class PkiRemoteExitCodes {

    private PkiRemoteExitCodes() {
    }

    /**
     * Returns the stable exit code for one terminal (or wait-exhausted) remote result.
     *
     * @param result terminal remote result
     * @return stable process exit code
     */
    /* default */ static int from(PkiRemoteResult result) {
        return switch (result) {
            case PkiRemoteResult.Succeeded ignored -> PkiExitCodes.SUCCESS;
            case PkiRemoteResult.Pending ignored -> PkiExitCodes.EXTERNAL_OUTCOME_UNKNOWN;
            case PkiRemoteResult.ApprovalRequired ignored -> PkiExitCodes.VALIDATION_OR_POLICY;
            case PkiRemoteResult.Failed failure -> fromClassification(failure.classification());
        };
    }

    /**
     * Maps one server failure classification string to a stable exit code.
     *
     * @param classification server failure classification
     * @return stable process exit code
     */
    /* default */ static int fromClassification(String classification) {
        return switch (classification) {
            case "VALIDATION_FAILURE", "POLICY_REJECTION", "AUTHORIZATION_DENIED" ->
                PkiExitCodes.VALIDATION_OR_POLICY;
            case "NOT_FOUND", "CONFLICT" -> PkiExitCodes.NOT_FOUND_OR_CONFLICT;
            case "RECOVERY_REQUIRED" -> PkiExitCodes.RECOVERY_REQUIRED;
            case "EXTERNAL_OUTCOME_UNKNOWN", "DEADLINE_EXCEEDED" -> PkiExitCodes.EXTERNAL_OUTCOME_UNKNOWN;
            case "RESOURCE_FAILURE", "OVERLOADED" -> PkiExitCodes.RESOURCE_FAILURE;
            case "CANCELLED" -> PkiExitCodes.CANCELLED;
            default -> PkiExitCodes.INTERNAL_FAILURE;
        };
    }
}
