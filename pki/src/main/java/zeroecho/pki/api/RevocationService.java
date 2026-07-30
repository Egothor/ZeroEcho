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

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationJournal;
import zeroecho.pki.api.revocation.RevocationQuery;

/**
 * Authoritative revocation transition and journal administration.
 */
public interface RevocationService {

    /**
     * Places a credential on hold.
     *
     * @param command hold command
     * @return committed journal
     */
    RevocationJournal hold(RevocationCommand.Hold command);

    /**
     * Removes an existing hold.
     *
     * @param command unhold command
     * @return committed journal
     */
    RevocationJournal unhold(RevocationCommand.Unhold command);

    /**
     * Permanently revokes a credential.
     *
     * @param command permanent revocation command
     * @return committed journal
     */
    RevocationJournal revokePermanently(RevocationCommand.RevokePermanently command);

    /**
     * Retrieves the authoritative journal for one credential.
     *
     * @param credentialId credential identifier
     * @return journal when present
     */
    Optional<RevocationJournal> get(PkiId credentialId);

    /**
     * Searches authoritative journals by their latest transition.
     *
     * @param query administrative query
     * @return matching journals
     */
    List<RevocationJournal> search(RevocationQuery query);
}
