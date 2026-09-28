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

import zeroecho.core.io.CancellationSignal;
import zeroecho.pki.application.PkiOperationOutcome;

/**
 * Execution seam that decouples the sequential {@link PkiPlanExecutor} from any
 * concrete backend.
 *
 * <p>The executor binds typed operations from the stable registry and then hands
 * each one to a transport for execution. The in-process
 * {@link LocalPkiOperationTransport} runs the operation against a lifecycle-owned
 * {@code PkiSession}; a remote deployment executes the same closed operation model
 * against a running {@code pki-server} over its mutual-TLS admin API. Introducing
 * this abstraction lets the executor run against either backend without any change
 * to its plan orchestration, reference resolution, or failure policy.</p>
 *
 * @implNote The remote administrative transport
 *           ({@link RemotePkiOperationTransport}) deliberately uses a richer
 *           result model than {@link PkiOperationOutcome} because it must surface
 *           the {@code APPROVAL_REQUIRED} outcome (with its operation commitment)
 *           and untyped server-control operation identifiers, neither of which the
 *           closed local outcome model expresses. It is therefore a sibling of
 *           this seam rather than an implementation of it.
 */
@FunctionalInterface
interface PkiOperationTransport extends AutoCloseable {

    /**
     * Executes one validated typed operation synchronously on the caller thread.
     *
     * @param operation validated typed operation
     * @param cancellation cooperative cancellation signal
     * @return completed, pending, or safely-classified failure outcome
     */
    PkiLocalResult execute(PkiLocalCommand operation, CancellationSignal cancellation);

    /**
     * Releases any transport-owned resources. The default releases nothing so a
     * transport that borrows an externally-owned session need not close it.
     *
     * @throws Exception if resource release fails
     */
    @Override
    default void close() throws Exception {
        // No transport-owned resource by default.
    }
}
