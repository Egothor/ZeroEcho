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

import java.util.Optional;

import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.spi.store.RevocationHistory;
import zeroecho.pki.spi.store.RevocationSnapshot;

/**
 * Authoritative revocation transition, current-state, and history administration.
 */
public interface RevocationService {

    /**
     * Places a credential on hold.
     *
     * @param command hold command
     * @return committed current state
     */
    RevocationRecord hold(RevocationCommand.Hold command);

    /**
     * Removes an existing hold.
     *
     * @param command unhold command
     * @return committed current state
     */
    RevocationRecord unhold(RevocationCommand.Unhold command);

    /**
     * Permanently revokes a credential.
     *
     * @param command permanent revocation command
     * @return committed current state
     */
    RevocationRecord revokePermanently(RevocationCommand.RevokePermanently command);

    /**
     * Retrieves the validated current state for one credential.
     *
     * @param credentialId credential identifier
     * @return current state when present
     */
    Optional<RevocationRecord> get(PkiId credentialId);

    /**
     * Opens the authoritative transition history for one credential.
     *
     * @param credentialId credential identifier
     * @return closeable bounded-memory history cursor
     */
    RevocationHistory history(PkiId credentialId);

    /**
     * Searches a stable ordered population view by current transition.
     *
     * @param query administrative query
     * @return closeable stable ordered view whose cursor yields matching states
     */
    RevocationSnapshot search(RevocationQuery query);
}
