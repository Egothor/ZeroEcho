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
package zeroecho.pki.api.backup;

import java.util.List;
import java.util.Objects;
import zeroecho.pki.api.PkiId;

/**
 * Immutable local restore outcome. Staging never means that the replacement is active.
 * @param restoreId stable restore identity
 * @param state acknowledged progress or explicit publication uncertainty
 * @param issues immutable, non-sensitive diagnostic codes
 */
public record RestoreStatus(PkiId restoreId, State state, List<String> issues) {
    /** Validates identity and takes an immutable copy of the issue codes. */
    public RestoreStatus {
        Objects.requireNonNull(restoreId, "restoreId");
        Objects.requireNonNull(state, "state");
        issues = List.copyOf(issues);
    }

    /** Observable restore outcomes. */
    public enum State {
        /** Prepared durably; closing and reopening the store is required. */
        STAGED,
        /** Replacement was opened, recovered and closed successfully before publication. */
        ACTIVATED,
        /** Replacement was rejected or cold activation was rolled back. */
        FAILED,
        /** Publication was not acknowledged; cold reconciliation must determine its outcome. */
        UNCERTAIN
    }
}
