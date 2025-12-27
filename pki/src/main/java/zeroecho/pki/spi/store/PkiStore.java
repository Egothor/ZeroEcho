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
package zeroecho.pki.spi.store;

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevokedRecord;
import zeroecho.pki.api.status.StatusObject;

/**
 * Persistence abstraction for PKI state.
 *
 * <p>
 * This Service Provider Interface (SPI) defines the authoritative storage
 * contract for all PKI-managed state, including CA entities, issued
 * credentials, certification requests, revocations, status objects, profiles,
 * publications, and policy traces.
 * </p>
 *
 * <p>
 * The interface is intentionally coarse-grained and framework-agnostic.
 * Implementations are responsible for providing appropriate durability,
 * consistency, and concurrency guarantees according to the deployment model
 * (filesystem, embedded storage, RDBMS, distributed store, etc.).
 * </p>
 *
 * <p>
 * <strong>Security requirements:</strong>
 * </p>
 * <ul>
 * <li>Private key material MUST NOT be persisted.</li>
 * <li>Secrets must never be stored in cleartext.</li>
 * <li>Stored objects must be treated as immutable unless explicitly
 * replaced.</li>
 * </ul>
 */
public interface PkiStore {

    /**
     * Persists or updates a Certificate Authority (CA) record.
     *
     * <p>
     * Implementations must ensure that CA records are stored atomically. Replacing
     * an existing CA record must preserve historical integrity (e.g., previously
     * issued credentials must remain resolvable).
     * </p>
     *
     * @param record CA record to persist
     * @throws IllegalArgumentException if {@code record} is null
     * @throws RuntimeException         if persistence fails
     */
    void putCa(CaRecord record);

    /**
     * Retrieves a CA record by its identifier.
     *
     * @param caId CA identifier
     * @return CA record if present, otherwise {@link Optional#empty()}
     * @throws IllegalArgumentException if {@code caId} is null
     * @throws RuntimeException         if retrieval fails
     */
    Optional<CaRecord> getCa(PkiId caId);

    /**
     * Lists all CA records known to the store.
     *
     * <p>
     * No filtering is applied at this level; higher layers are expected to perform
     * query-based filtering.
     * </p>
     *
     * @return list of CA records (never null)
     * @throws RuntimeException if listing fails
     */
    List<CaRecord> listCas();

    /**
     * Persists an issued credential.
     *
     * <p>
     * Credentials are immutable once stored. Re-inserting an existing credential
     * identifier should either be idempotent or rejected, depending on
     * implementation policy.
     * </p>
     *
     * @param credential credential to persist
     * @throws IllegalArgumentException if {@code credential} is null
     * @throws RuntimeException         if persistence fails
     */
    void putCredential(Credential credential);

    /**
     * Retrieves an issued credential by its identifier.
     *
     * @param credentialId credential identifier
     * @return credential if present
     * @throws IllegalArgumentException if {@code credentialId} is null
     * @throws RuntimeException         if retrieval fails
     */
    Optional<Credential> getCredential(PkiId credentialId);

    /**
     * Persists a parsed certification request.
     *
     * <p>
     * Stored requests are used for audit, correlation, re-issuance, and ACME-like
     * workflows.
     * </p>
     *
     * @param request parsed certification request
     * @throws IllegalArgumentException if {@code request} is null
     * @throws RuntimeException         if persistence fails
     */
    void putRequest(ParsedCertificationRequest request);

    /**
     * Retrieves a stored certification request.
     *
     * @param requestId request identifier
     * @return parsed request if present
     * @throws IllegalArgumentException if {@code requestId} is null
     * @throws RuntimeException         if retrieval fails
     */
    Optional<ParsedCertificationRequest> getRequest(PkiId requestId);

    /**
     * Persists a revocation record.
     *
     * <p>
     * Revocation records are authoritative inputs for generating revocation status
     * objects (CRLs, OCSP, etc.).
     * </p>
     *
     * @param record revocation record
     * @throws IllegalArgumentException if {@code record} is null
     * @throws RuntimeException         if persistence fails
     */
    void putRevocation(RevokedRecord record);

    /**
     * Retrieves the revocation record for a credential.
     *
     * @param credentialId credential identifier
     * @return revocation record if present
     * @throws IllegalArgumentException if {@code credentialId} is null
     * @throws RuntimeException         if retrieval fails
     */
    Optional<RevokedRecord> getRevocation(PkiId credentialId);

    /**
     * Lists all revocation records.
     *
     * @return list of revocation records (never null)
     * @throws RuntimeException if listing fails
     */
    List<RevokedRecord> listRevocations();

    /**
     * Persists a generated status object.
     *
     * <p>
     * Status objects include CRLs, delta CRLs, OCSP responses, or
     * framework-specific revocation lists.
     * </p>
     *
     * @param object status object to persist
     * @throws IllegalArgumentException if {@code object} is null
     * @throws RuntimeException         if persistence fails
     */
    void putStatusObject(StatusObject object);

    /**
     * Retrieves a status object by its identifier.
     *
     * @param statusObjectId status object identifier
     * @return status object if present
     * @throws IllegalArgumentException if {@code statusObjectId} is null
     * @throws RuntimeException         if retrieval fails
     */
    Optional<StatusObject> getStatusObject(PkiId statusObjectId);

    /**
     * Lists all status objects issued by a given CA.
     *
     * @param issuerCaId issuer CA identifier
     * @return list of status objects (never null)
     * @throws IllegalArgumentException if {@code issuerCaId} is null
     * @throws RuntimeException         if listing fails
     */
    List<StatusObject> listStatusObjects(PkiId issuerCaId);

    /**
     * Persists a publication record.
     *
     * <p>
     * Publication records provide traceability and operational diagnostics for
     * artifact distribution.
     * </p>
     *
     * @param record publication record
     * @throws IllegalArgumentException if {@code record} is null
     * @throws RuntimeException         if persistence fails
     */
    void putPublicationRecord(PublicationRecord record);

    /**
     * Lists all publication records.
     *
     * @return list of publication records (never null)
     * @throws RuntimeException if listing fails
     */
    List<PublicationRecord> listPublicationRecords();

    /**
     * Persists or updates a certificate profile.
     *
     * @param profile certificate profile
     * @throws IllegalArgumentException if {@code profile} is null
     * @throws RuntimeException         if persistence fails
     */
    void putProfile(CertificateProfile profile);

    /**
     * Retrieves a certificate profile by identifier.
     *
     * @param profileId profile identifier
     * @return profile if present
     * @throws IllegalArgumentException if {@code profileId} is null or blank
     * @throws RuntimeException         if retrieval fails
     */
    Optional<CertificateProfile> getProfile(String profileId);

    /**
     * Lists all stored certificate profiles.
     *
     * @return list of profiles (never null)
     * @throws RuntimeException if listing fails
     */
    List<CertificateProfile> listProfiles();

    /**
     * Persists a policy evaluation trace.
     *
     * <p>
     * Policy traces are used for explainability, audit, and compliance evidence.
     * They must never contain sensitive data.
     * </p>
     *
     * @param trace policy trace
     * @throws IllegalArgumentException if {@code trace} is null
     * @throws RuntimeException         if persistence fails
     */
    void putPolicyTrace(PolicyTrace trace);

    /**
     * Retrieves a policy trace by decision identifier.
     *
     * @param decisionId policy decision identifier
     * @return policy trace if present
     * @throws IllegalArgumentException if {@code decisionId} is null
     * @throws RuntimeException         if retrieval fails
     */
    Optional<PolicyTrace> getPolicyTrace(PkiId decisionId);
}
