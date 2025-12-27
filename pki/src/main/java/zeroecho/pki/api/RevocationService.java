/*******************************************************************************
 * Copyright (C) 2025, Leo Galambos
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
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
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/
package zeroecho.pki.api;

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.revocation.HoldCommand;
import zeroecho.pki.api.revocation.RevocationQuery;
import zeroecho.pki.api.revocation.RevokeCommand;
import zeroecho.pki.api.revocation.RevokedRecord;
import zeroecho.pki.api.revocation.UnholdCommand;

/**
 * Revocation operations and revocation record management.
 */
public interface RevocationService {

    /**
     * Revokes a credential.
     *
     * @param command revoke command
     * @return revocation record
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if revocation fails
     */
    RevokedRecord revoke(RevokeCommand command);

    /**
     * Places a credential on hold.
     *
     * @param command hold command
     * @return revocation record
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if hold fails
     */
    RevokedRecord hold(HoldCommand command);

    /**
     * Removes a hold from a credential.
     *
     * @param command unhold command
     * @return revocation record
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if unhold fails
     */
    RevokedRecord unhold(UnholdCommand command);

    /**
     * Retrieves revocation record for a credential.
     *
     * @param credentialId credential id
     * @return record if present
     * @throws IllegalArgumentException if {@code credentialId} is null
     * @throws PkiException             if retrieval fails
     */
    Optional<RevokedRecord> get(PkiId credentialId);

    /**
     * Searches revocation records.
     *
     * @param query query constraints
     * @return matching records
     * @throws IllegalArgumentException if {@code query} is null
     * @throws PkiException             if search fails
     */
    List<RevokedRecord> search(RevocationQuery query);
}
