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

import zeroecho.pki.api.ca.CaCreateCommand;
import zeroecho.pki.api.ca.CaImportCommand;
import zeroecho.pki.api.ca.CaKeyRotationCommand;
import zeroecho.pki.api.ca.CaQuery;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.CaRolloverCommand;
import zeroecho.pki.api.ca.CaState;
import zeroecho.pki.api.ca.IntermediateCertIssueCommand;
import zeroecho.pki.api.ca.IntermediateCreateCommand;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.credential.Credential;

/**
 * Manages Certificate Authority (CA) entities and their lifecycle.
 *
 * <p>
 * A CA entity represents an administrative unit capable of issuing credentials.
 * A CA entity may own multiple CA credentials over time to support
 * cross-signing, rollover, and key rotation.
 * </p>
 *
 * <p>
 * Private key material is never handled directly by the PKI module; the CA key
 * is referenced by {@link KeyRef} and resolved by runtime wiring.
 * </p>
 */
public interface CaService {

    /**
     * Creates a new root CA entity and issues its initial CA credential.
     *
     * @param command create command defining subject/profile and optional key
     *                reference
     * @return created CA identifier
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if creation fails due to policy, storage, or
     *                                  framework backend error
     */
    PkiId createRoot(CaCreateCommand command);

    /**
     * Imports an existing root CA into the PKI inventory.
     *
     * <p>
     * This registers a CA entity, associates it with a {@link KeyRef}, and persists
     * the existing CA credential. Import does not automatically imply trust; trust
     * anchor selection is a consumer decision.
     * </p>
     *
     * @param command import command including CA credential payload and key
     *                reference
     * @return imported CA identifier
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if import fails (e.g., inconsistent
     *                                  metadata, storage failure)
     */
    PkiId importRoot(CaImportCommand command);

    /**
     * Creates a new intermediate CA entity and issues its initial intermediate CA
     * credential.
     *
     * @param command intermediate creation command
     * @return created intermediate CA identifier
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if creation fails
     */
    PkiId createIntermediate(IntermediateCreateCommand command);

    /**
     * Issues a new CA credential for an existing intermediate CA entity.
     *
     * <p>
     * This operation enables cross-signing and renewal scenarios.
     * </p>
     *
     * @param command issuance command specifying issuer and subject CA entity
     * @return newly issued CA credential
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if issuance fails due to policy or backend
     *                                  errors
     */
    Credential issueIntermediateCertificate(IntermediateCertIssueCommand command);

    /**
     * Performs a CA credential rollover while keeping the same key reference.
     *
     * @param command rollover command
     * @return CA identifier (same CA id expected; returned for convenience)
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if rollover fails
     */
    PkiId rolloverCaCertificate(CaRolloverCommand command);

    /**
     * Rotates the CA key reference and issues new corresponding CA credentials.
     *
     * @param command key rotation command
     * @return CA identifier (same CA id expected; returned for convenience)
     * @throws IllegalArgumentException if {@code command} is invalid
     * @throws PkiException             if rotation fails
     */
    PkiId rotateCaKey(CaKeyRotationCommand command);

    /**
     * Updates CA operational state.
     *
     * @param caId   CA identifier
     * @param state  new CA state
     * @param reason non-empty operator-readable reason suitable for audit
     * @throws IllegalArgumentException if inputs are invalid
     * @throws PkiException             if CA does not exist or update fails
     */
    void setCaState(PkiId caId, CaState state, String reason);

    /**
     * Retrieves a CA record.
     *
     * <p>
     * The returned record contains ordered credential identifiers. Credential
     * content and metadata remain authoritative only through the configured
     * credential store.
     * </p>
     *
     * @param caId CA identifier
     * @return CA record
     * @throws IllegalArgumentException if {@code caId} is invalid
     * @throws PkiException             if CA does not exist
     */
    CaRecord getCa(PkiId caId);

    /**
     * Lists CA records matching query constraints.
     *
     * <p>
     * Returned records contain ordered credential identifiers rather than embedded
     * credential values.
     * </p>
     *
     * @param query query constraints
     * @return list of CA records
     * @throws IllegalArgumentException if {@code query} is invalid
     * @throws PkiException             if listing fails
     */
    List<CaRecord> listCas(CaQuery query);

    /** Returns one exact issuer generation owned by this PKI authority. */
    IssuerGeneration getIssuerGeneration(PkiId issuerId);

    /** Returns one exact immutable issuer chain path. */
    IssuerChainPath getIssuerChainPath(PkiId pathId);

    /** Lists all explicit paths for an exact issuer generation. */
    List<IssuerChainPath> listIssuerChainPaths(PkiId issuerId);

    /**
     * Atomically selects the exact issuer generation and path used for future
     * issuance and bundle construction.
     */
    void selectIssuancePath(PkiId caId, PkiId issuerId, PkiId pathId, String reason);

    /**
     * Registers an additional explicit path for an existing issuer generation by
     * appending one already-authoritative parent path.
     *
     * @return immutable registered path
     */
    IssuerChainPath registerIssuerChainPath(PkiId caId, PkiId issuerId, PkiId parentPathId);
}
