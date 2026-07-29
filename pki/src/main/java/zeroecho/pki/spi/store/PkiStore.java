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
package zeroecho.pki.spi.store;

import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.profile.CertificateProfile;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevokedRecord;
import zeroecho.pki.api.status.StatusObject;

/**
 * Persistence boundary for PKI state.
 *
 * <p>
 * This Service Provider Interface (SPI) defines durable storage for the PKI
 * domain model. Implementations may use a filesystem, database, or other
 * backend, but must preserve deterministic behavior, atomicity guarantees, and
 * must not leak secrets through logging or exception messages.
 * </p>
 *
 * <h2>Security</h2>
 * <p>
 * Implementations must protect persisted data appropriately (for example:
 * filesystem permissions, database ACLs). Sensitive material must never be
 * written to logs. Exceptions should avoid leaking secrets in their messages.
 * </p>
 *
 * <h2>Error handling</h2>
 * <p>
 * This SPI uses unchecked failures. Implementations should throw
 * {@link IllegalStateException} when an operation cannot be completed safely.
 * </p>
 */
public interface PkiStore extends SignWorkflowStore {

    /**
     * Persists or updates a Certificate Authority (CA) record.
     *
     * <p>
     * Implementations must store CA records atomically. Replacing an existing
     * record should be either fully visible or not visible at all.
     * </p>
     *
     * @param record CA record (never {@code null})
     * @throws NullPointerException  if {@code record} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putCa(CaRecord record);

    /**
     * Retrieves a CA record.
     *
     * @param caId CA identifier (never {@code null})
     * @return CA record if present
     * @throws NullPointerException  if {@code caId} is {@code null}
     * @throws IllegalStateException if retrieval fails
     */
    Optional<CaRecord> getCa(PkiId caId);

    /**
     * Lists all stored CA records.
     *
     * @return list of CA records (never {@code null})
     * @throws IllegalStateException if listing fails
     */
    List<CaRecord> listCas();

    /**
     * Persists a credential record.
     *
     * <p>
     * Credentials are typically immutable once issued. Implementations must ensure
     * that storing a credential is atomic and that the record remains retrievable
     * for its entire retention period.
     * </p>
     *
     * @param credential credential record (never {@code null})
     * @throws NullPointerException  if {@code credential} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putCredential(Credential credential);

    /**
     * Retrieves a credential record.
     *
     * @param credentialId credential identifier (never {@code null})
     * @return credential record if present
     * @throws NullPointerException  if {@code credentialId} is {@code null}
     * @throws IllegalStateException if retrieval fails
     */
    Optional<Credential> getCredential(PkiId credentialId);

    /**
     * Persists a parsed certification request.
     *
     * <p>
     * Requests are typically immutable artifacts. Implementations should treat them
     * as write-once records unless there is a clear need to support updates.
     * </p>
     *
     * @param request parsed request (never {@code null})
     * @throws NullPointerException  if {@code request} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putRequest(ParsedCertificationRequest request);

    /**
     * Retrieves a parsed certification request.
     *
     * @param requestId request identifier (never {@code null})
     * @return parsed request if present
     * @throws NullPointerException  if {@code requestId} is {@code null}
     * @throws IllegalStateException if retrieval fails
     */
    Optional<ParsedCertificationRequest> getRequest(PkiId requestId);

    /**
     * Persists or updates a revocation record.
     *
     * @param record revocation record (never {@code null})
     * @throws NullPointerException  if {@code record} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putRevocation(RevokedRecord record);

    /**
     * Retrieves a revocation record for a given credential.
     *
     * @param credentialId credential identifier (never {@code null})
     * @return revocation record if present
     * @throws NullPointerException  if {@code credentialId} is {@code null}
     * @throws IllegalStateException if retrieval fails
     */
    Optional<RevokedRecord> getRevocation(PkiId credentialId);

    /**
     * Lists all revocation records.
     *
     * @return list of revocation records (never {@code null})
     * @throws IllegalStateException if listing fails
     */
    List<RevokedRecord> listRevocations();

    /**
     * Persists a status object.
     *
     * <p>
     * Status objects are typically published artifacts (for example OCSP responses,
     * CRLs, or other status representations) and are usually immutable once
     * created.
     * </p>
     *
     * @param object status object (never {@code null})
     * @throws NullPointerException  if {@code object} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putStatusObject(StatusObject object);

    /**
     * Retrieves a status object.
     *
     * @param statusObjectId status object identifier (never {@code null})
     * @return status object if present
     * @throws NullPointerException  if {@code statusObjectId} is {@code null}
     * @throws IllegalStateException if retrieval fails
     */
    Optional<StatusObject> getStatusObject(PkiId statusObjectId);

    /**
     * Lists status objects issued under a specific issuer CA.
     *
     * <p>
     * This method exists to support issuer-scoped publication and retrieval
     * patterns (for example: listing all CRLs or other status artifacts produced by
     * a given CA).
     * </p>
     *
     * @param issuerCaId issuer CA identifier (never {@code null})
     * @return list of status objects for the issuer (never {@code null})
     * @throws NullPointerException  if {@code issuerCaId} is {@code null}
     * @throws IllegalStateException if listing fails
     */
    List<StatusObject> listStatusObjects(PkiId issuerCaId);

    /**
     * Persists or updates a publication record.
     *
     * <p>
     * Publication records describe distribution state (for example: where and when
     * an object was published). These records may be used for operational
     * monitoring and reconciliation.
     * </p>
     *
     * @param record publication record (never {@code null})
     * @throws NullPointerException  if {@code record} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putPublicationRecord(PublicationRecord record);

    /**
     * Lists all publication records.
     *
     * @return list of publication records (never {@code null})
     * @throws IllegalStateException if listing fails
     */
    List<PublicationRecord> listPublicationRecords();

    /**
     * Persists or updates a certificate profile.
     *
     * <p>
     * A certificate profile represents a reusable issuance template (for example:
     * VPN client, VPN server, S/MIME). The profile may be referenced by higher
     * layers during certificate issuance.
     * </p>
     *
     * @param profile certificate profile (never {@code null})
     * @throws NullPointerException  if {@code profile} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putProfile(CertificateProfile profile);

    /**
     * Retrieves a certificate profile by profile identifier.
     *
     * <p>
     * The identifier is a stable, system-defined key (not a display name). It
     * should be suitable for configuration and API use (for example:
     * {@code "vpn-client"}).
     * </p>
     *
     * @param profileId profile identifier (never {@code null})
     * @return profile if present
     * @throws NullPointerException  if {@code profileId} is {@code null}
     * @throws IllegalStateException if retrieval fails
     */
    Optional<CertificateProfile> getProfile(String profileId);

    /**
     * Lists all stored certificate profiles.
     *
     * @return list of profiles (never {@code null})
     * @throws IllegalStateException if listing fails
     */
    List<CertificateProfile> listProfiles();

    /**
     * Persists a policy trace.
     *
     * <p>
     * Policy traces capture decision-making and evaluation information. These
     * records may contain sensitive meta-information and must be protected by the
     * underlying store.
     * </p>
     *
     * @param trace policy trace (never {@code null})
     * @throws NullPointerException  if {@code trace} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putPolicyTrace(PolicyTrace trace);

    /**
     * Retrieves a policy trace.
     *
     * @param decisionId policy decision identifier (never {@code null})
     * @return policy trace if present
     * @throws NullPointerException  if {@code decisionId} is {@code null}
     * @throws IllegalStateException if retrieval fails
     */
    Optional<PolicyTrace> getPolicyTrace(PkiId decisionId);

    // -------------------------------------------------------------------------
    // Workflow continuation state (orchestration)
    // -------------------------------------------------------------------------

    /**
     * Persists or updates an orchestrator workflow continuation record.
     *
     * <p>
     * The workflow payload may be encrypted. Implementations must treat it as
     * sensitive and must not log it.
     * </p>
     *
     * @param record workflow state record (never {@code null})
     * @throws NullPointerException  if {@code record} is {@code null}
     * @throws IllegalStateException if persistence fails
     */
    void putWorkflowState(WorkflowStateRecord record);

    /**
     * Retrieves workflow continuation state for a given operation.
     *
     * @param opId operation identifier (never {@code null})
     * @return workflow state record if present
     * @throws NullPointerException  if {@code opId} is {@code null}
     * @throws IllegalStateException if retrieval fails
     */
    Optional<WorkflowStateRecord> getWorkflowState(PkiId opId);

    /**
     * Deletes workflow continuation state for a given operation.
     *
     * <p>
     * Implementations may retain historical snapshots according to their history
     * policy. Deletion guarantees only removal of the current record.
     * </p>
     *
     * @param opId operation identifier (never {@code null})
     * @throws NullPointerException  if {@code opId} is {@code null}
     * @throws IllegalStateException if deletion fails
     */
    void deleteWorkflowState(PkiId opId);

    /**
     * Lists workflow continuation state records.
     *
     * <p>
     * This method is intended for administrative reconciliation and recovery.
     * Higher layers should apply access control and filtering as appropriate.
     * </p>
     *
     * @return list of workflow state records (never {@code null})
     * @throws IllegalStateException if listing fails
     */
    List<WorkflowStateRecord> listWorkflowStates();
}
