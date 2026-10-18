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
package zeroecho.pki.api;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.credential.CredentialQuery;
import zeroecho.pki.api.credential.CredentialStatus;

/**
 * Inventory and reporting service for issued credentials.
 */
public interface CredentialInventoryService {

    /**
     * Retrieves a credential by id.
     *
     * @param credentialId credential id
     * @return credential if present
     * @throws IllegalArgumentException if {@code credentialId} is null
     * @throws PkiException             if retrieval fails
     */
    Optional<Credential> get(PkiId credentialId);

    /**
     * Finds a credential by issuer CA and serial/unique identifier.
     *
     * @param issuerCaId       issuer CA id
     * @param serialOrUniqueId serial/unique id
     * @return credential if present
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if lookup fails
     */
    Optional<Credential> findByIssuerSerial(PkiId issuerCaId, String serialOrUniqueId);

    /**
     * Lists credentials bound to the same public key identifier.
     *
     * @param publicKeyId public key id
     * @return credentials
     * @throws IllegalArgumentException if {@code publicKeyId} is null
     * @throws PkiException             if lookup fails
     */
    List<Credential> listByPublicKeyId(PkiId publicKeyId);

    /**
     * Searches credentials by query constraints.
     *
     * @param query query constraints
     * @return matching credentials
     * @throws IllegalArgumentException if {@code query} is null
     * @throws PkiException             if search fails
     */
    List<Credential> search(CredentialQuery query);

    /**
     * Computes credential status at a given time.
     *
     * @param credentialId credential id
     * @param now          evaluation time
     * @return computed status
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if evaluation fails
     */
    CredentialStatus computeStatus(PkiId credentialId, Instant now);
}
