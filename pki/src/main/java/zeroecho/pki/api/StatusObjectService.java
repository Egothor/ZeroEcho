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

import zeroecho.pki.api.status.StatusObject;
import zeroecho.pki.api.status.StatusObjectGenerateCommand;
import zeroecho.pki.api.status.StatusObjectQuery;
import zeroecho.pki.api.status.StatusObjectType;

/**
 * Status object generation and retrieval.
 *
 * <p>
 * Status objects include CRLs, delta CRLs, OCSP responses, or
 * framework-specific revocation lists.
 * </p>
 */
public interface StatusObjectService {

    /**
     * Generates a new status object for an issuer CA.
     *
     * @param command generation command
     * @return generated status object
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if generation fails
     */
    StatusObject generate(StatusObjectGenerateCommand command);

    /**
     * Retrieves the latest status object of a given type for an issuer CA.
     *
     * @param issuerCaId issuer CA id
     * @param type       status object type
     * @return latest status object if present
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if retrieval fails
     */
    Optional<StatusObject> getLatest(PkiId issuerCaId, StatusObjectType type);

    /**
     * Lists status objects matching query constraints.
     *
     * @param query query constraints
     * @return matching status objects
     * @throws IllegalArgumentException if {@code query} is invalid
     * @throws PkiException             if listing fails
     */
    List<StatusObject> list(StatusObjectQuery query);
}
