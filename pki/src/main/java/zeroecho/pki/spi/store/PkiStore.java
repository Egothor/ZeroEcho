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

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.orch.WorkflowStateRecord;
import zeroecho.pki.api.policy.PolicyTrace;
import zeroecho.pki.api.profile.ActiveCertificateProfile;
import zeroecho.pki.api.profile.CertificateProfileRef;
import zeroecho.pki.api.profile.ImportedCertificateProfileVersion;
import zeroecho.pki.api.publication.PublicationCursor;
import zeroecho.pki.api.publication.PublicationRecord;
import zeroecho.pki.api.request.ParsedCertificationRequest;
import zeroecho.pki.api.revocation.RevocationCommand;
import zeroecho.pki.api.revocation.RevocationRecord;
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
 * <h2>Publication recovery ownership</h2>
 * <p>
 * Before an instance is exposed to callers, its implementation must hold
 * exclusive publication-runtime ownership and validate the complete publication
 * namespace in one stable view. Any abandoned
 * {@link zeroecho.pki.api.publication.PublicationStatus#DISPATCH_PREPARED}
 * operation must be durably changed to
 * {@link zeroecho.pki.api.publication.PublicationStatus#OUTCOME_UNKNOWN} before
 * exposure, without invoking a publisher. Once exposed, the store must not
 * reclassify a prepared operation because it may represent an active dispatch in
 * the owning runtime. A backend that supports simultaneous runtimes must provide
 * durable session or lease fencing with equivalent safety instead of unconditional
 * open-time recovery.
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
     * Returns the runtime-owned durable streaming-content store.
     *
     * @return staged-content store used by this PKI store
     */
    StagedContentStore stagedContent();

    /**
     * Persists or updates a Certificate Authority (CA) record.
     *
     * <p>
     * Implementations must store CA records atomically. Replacing an existing
     * record should be either fully visible or not visible at all. Every
     * identifier in {@link CaRecord#credentialIds()} must resolve through
     * {@link #getCredential(PkiId)} before the CA record is published.
     * </p>
     *
     * @param record CA record (never {@code null})
     * @throws NullPointerException  if {@code record} is {@code null}
     * @throws IllegalStateException if persistence fails or a referenced
     *                               credential is missing or invalid
     */
    void putCa(CaRecord record);

    /**
     * Retrieves a CA record.
     *
     * @param caId CA identifier (never {@code null})
     * @return CA record if present; all credential identifiers have been validated
     *         against the standalone credential authority
     * @throws NullPointerException  if {@code caId} is {@code null}
     * @throws IllegalStateException if retrieval fails or a referenced credential
     *                               is missing or invalid
     */
    Optional<CaRecord> getCa(PkiId caId);

    /**
     * Lists all stored CA records.
     *
     * @return list of CA records (never {@code null}); every returned credential
     *         identifier has been validated against the standalone credential
     *         authority
     * @throws IllegalStateException if listing fails or a referenced credential is
     *                               missing or invalid
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
     * Atomically validates and appends one legal revocation transition.
     *
     * @param command        trusted transition command
     * @param transitionTime authoritative transition time
     * @return committed current state
     */
    RevocationRecord transitionRevocation(RevocationCommand command, Instant transitionTime);

    /**
     * Retrieves the validated current revocation state for a credential.
     * Disk probing is expected constant time and is linear in index capacity in
     * the worst collision case; auxiliary heap use is constant.
     *
     * @param credentialId credential identifier
     * @return current state when present
     */
    Optional<RevocationRecord> getRevocation(PkiId credentialId);

    /**
     * Opens a bounded-memory cursor over one credential's authoritative history.
     * Opening is constant time. The first advance validates the captured global
     * prefix; consuming the history performs at most two linear passes over that
     * prefix and uses constant auxiliary heap.
     *
     * @param credentialId exact credential identity
     * @return closeable history cursor captured at the current log head
     * @throws IllegalStateException if the authoritative history cannot be opened
     */
    RevocationHistory openRevocationHistory(PkiId credentialId);

    /**
     * Opens a stable restartable streaming snapshot of authoritative revocations.
     * An exact checkpoint opens in constant time after validation. Otherwise the
     * implementation may perform bounded-memory external sorting over the current
     * population; cursors themselves use constant auxiliary heap per entry.
     *
     * @return revocation snapshot
     * @throws IllegalStateException if the snapshot cannot be opened
     */
    RevocationSnapshot openRevocationSnapshot();

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
     * Creates one publication operation if absent.
     *
     * <p>
     * An identical replay is idempotent. A different record under the same identity
     * fails closed. The implementation must use its finite transactional metadata
     * authority and must not create a sidecar record.
     * </p>
     *
     * @param record publication record (never {@code null})
     * @throws NullPointerException  if {@code record} is {@code null}
     * @return committed record, including an identical existing record
     * @throws IllegalArgumentException if the identity conflicts
     * @throws IllegalStateException if persistence fails or is uncertain
     */
    PublicationRecord createPublicationRecord(PublicationRecord record);

    /**
     * Reads one publication operation by exact semantic identity.
     *
     * @param publicationId operation identity
     * @return current durable record, or empty when absent
     */
    Optional<PublicationRecord> getPublicationRecord(PkiId publicationId);

    /**
     * Atomically replaces one exact observed publication state.
     *
     * @param expected exact current record
     * @param replacement valid next state with identical immutable fields
     * @return {@code true} when committed; {@code false} on a concurrent conflict
     * @throws IllegalArgumentException if identities, immutable fields or the state
     *         transition are invalid
     * @throws IllegalStateException if persistence fails or is uncertain
     */
    boolean replacePublicationRecord(PublicationRecord expected, PublicationRecord replacement);

    /**
     * Opens a stable ordered cursor over the complete publication namespace.
     *
     * @return closeable cursor whose heap does not grow with returned records
     * @throws IllegalStateException if the stable view cannot be opened
     */
    PublicationCursor openPublicationRecords();

    /**
     * Atomically imports one immutable validated profile version.
     *
     * <p>
     * Every version stored under one logical profile ID must have the same
     * certificate kind. An implementation must reject an import whose kind differs
     * from any already imported version for that ID. For an existing identical ID
     * and version, exact canonical-reference equality is idempotent and returns the
     * committed version; a different reference for that same version is a version
     * conflict. This same-version decision takes precedence over the cross-version
     * kind check.
     * </p>
     *
     * @param version validated immutable version to import
     * @return the newly committed version or the identical existing version
     * @throws RuntimeException if validation, kind consistency, conflict handling,
     *                          or durable persistence fails
     */
    ImportedCertificateProfileVersion importProfileVersion(ImportedCertificateProfileVersion version);

    /** Retrieves one imported version. */
    Optional<ImportedCertificateProfileVersion> getProfileVersion(String profileId, long profileVersion);

    /** Lists imported versions in ascending version order. */
    List<ImportedCertificateProfileVersion> listProfileVersions(String profileId);

    /** Atomically activates one imported version. */
    CertificateProfileRef activateProfile(String profileId, long profileVersion);

    /** Retrieves the current active reference. */
    Optional<CertificateProfileRef> getActiveProfileRef(String profileId);

    /** Resolves the exact active version and validated runtime projection. */
    ActiveCertificateProfile requireActiveProfile(String profileId);

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
