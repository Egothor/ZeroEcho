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
package zeroecho.pki.api.schedule;

import java.util.List;
import java.util.Optional;
import zeroecho.core.io.CancellationSignal;

/** Borrowed session service for durable recurring status generation and recovery. */
public interface StatusScheduleCoordinator {
    /**
     * Lists enabled schedules and unresolved executions, including disabled executions.
     * @param after exclusive opaque cursor from the preceding configuration
     * @param limit maximum rows, 1 through 1001
     * @param cancellation cooperative cancellation
     * @return bounded page ordered by authority and status type
     */
    List<StatusScheduleState> listWork(Optional<String> after, int limit, CancellationSignal cancellation);

    /**
     * Reconciles one schedule, resuming any accepted signature rather than preparing a replacement.
     * At most one new catch-up execution follows reconciliation of a previously committed effect.
     * @param observed previously listed state; concurrent edits are reread
     * @param cancellation cooperative cancellation; cancellation does not revoke accepted work
     * @return latest durable progress
     */
    StatusScheduleState reconcile(StatusScheduleState observed, CancellationSignal cancellation);
}
