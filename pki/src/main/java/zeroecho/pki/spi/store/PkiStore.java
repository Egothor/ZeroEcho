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
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;

import zeroecho.pki.api.PkiId;
import zeroecho.pki.api.ca.CaRecord;
import zeroecho.pki.api.ca.IssuerChainPath;
import zeroecho.pki.api.ca.IssuerGeneration;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallenge;
import zeroecho.pki.api.confirmation.CredentialConfirmationChallengeIssuance;
import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationLifecycle;
import zeroecho.pki.api.confirmation.CredentialConfirmationProofCas;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewCursor;
import zeroecho.pki.api.confirmation.CredentialConfirmationReviewPage;
import zeroecho.pki.api.credential.Credential;
import zeroecho.pki.api.issuance.IssuanceIntent;
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
@SuppressWarnings("PMD.ExcessivePublicCount")
public interface PkiStore extends SignWorkflowStore, DomainContinuationStore, AutoCloseable { // NOPMD - TooManyMethods: one cohesive strict-schema or store-transaction ownership contract.

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
     * identifier in {@link CaRecord#issuerIds()} must resolve through
     * {@link #getIssuerGeneration(PkiId)} before the CA record is published.
     * </p>
     *
     * @param record CA record (never {@code null})
     * @throws NullPointerException  if {@code record} is {@code null}
     * @throws IllegalStateException if persistence fails or a referenced
     *                               credential is missing or invalid
     */
    void putCa(CaRecord record);

    /**
     * Atomically replaces an existing CA record only while its complete value equals
     * {@code expected}.
     *
     * <p>The expected and replacement records must identify the same CA. Comparison
     * and conditional publication share one authoritative snapshot and head revision.
     * Existing credential, generation, path, append-only membership and history
     * validation apply to the replacement. A successful publication atomically
     * updates the current head and any configured membership/history rows.</p>
     *
     * <p>A missing or unequal current value, or a definite commit conflict, returns
     * {@code false} without publishing replacement rows. Other storage failures,
     * acknowledgement failures and uncertain outcomes throw; they are never reported
     * as a comparison mismatch. An uncertain attempt must not be blindly retried.</p>
     *
     * @param expected complete previously observed CA record
     * @param replacement complete replacement record for the same CA
     * @return {@code true} after confirmed publication, or {@code false} for absence,
     *         an unequal current value or a definite concurrent-write conflict
     * @throws NullPointerException if either record is {@code null}
     * @throws IllegalArgumentException if the records identify different CAs
     * @throws IllegalStateException if reference validation or definite persistence fails
     * @throws zeroecho.pki.api.PkiException if durable publication or acknowledgement
     *         cannot be confirmed; the owning store may require recovery
     */
    boolean replaceCa(CaRecord expected, CaRecord replacement);

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
     * Returns a bounded canonical keyset page of CA records.
     *
     * @param afterCaId optional exclusive lower bound
     * @param limit positive finite page size
     * @return records ordered by canonical CA identity
     */
    List<CaRecord> listCasPage(Optional<PkiId> afterCaId, int limit);

    /**
     * Selects an authorized authority page before its limit is applied.
     * @param after exclusive wire identifier
     * @param limit maximum rows including lookahead, 1 through 1001
     * @param include short-lived authorization predicate, never retained
     * @param cancellation cooperative signal checked for every scanned candidate
     * @return immutable page in ascending identifier order
     */
    List<CaRecord> selectAuthoritiesPage(Optional<String> after, int limit,
            java.util.function.Predicate<CaRecord> include, zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Visits known issuing-key references from authoritative CA metadata without collecting all CAs.
     * The callback is synchronous, may see duplicates, and is never retained.
     * @param visitor consumer of non-secret key references
     * @param cancellation cooperative cancellation checked for every record
     */
    void visitAuthorityKeyReferences(java.util.function.Consumer<zeroecho.pki.api.KeyRef> visitor,
            zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Lists logical profile IDs after an exclusive identifier, in ascending string order.
     * A filesystem store scans profile directories with O(N log L) time and O(L) auxiliary memory.
     * @param after exclusive identifier, or empty for the first page
     * @param limit maximum rows, 1 through 1001 (including presentation lookahead)
     * @param include short-lived authorization predicate, never retained
     * @param cancellation cooperative signal checked for every scanned candidate
     * @return immutable bounded identifier page
     */
    List<String> listProfileIdsPage(Optional<String> after, int limit, java.util.function.Predicate<String> include, zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Lists request metadata in ascending request-ID order. Subject data is not suitable for selection responses.
     * @param after exclusive request identifier
     * @param limit maximum rows, 1 through 1001
     * @param include short-lived authorization predicate, never retained
     * @param cancellation cooperative signal checked for every scanned candidate
     * @return immutable bounded page
     */
    List<RequestSelection> listRequestsPage(Optional<String> after, int limit, java.util.function.Predicate<RequestSelection> include, zeroecho.core.io.CancellationSignal cancellation);

    /** Safe immutable request-selection metadata; contains no subject, SAN, CSR or key bytes.
     * @param requestId authoritative request identity
     * @param formatId parsed format
     * @param profileId persisted optional requested profile
     */
    record RequestSelection(PkiId requestId, zeroecho.pki.api.FormatId formatId, Optional<String> profileId) { }

    /**
     * Lists credentials for one authority in ascending credential-ID order.
     * @param authorityId authoritative issuer authority
     * @param after exclusive credential identifier
     * @param limit maximum rows, 1 through 1001
     * @param include short-lived authorization predicate, never retained
     * @param cancellation cooperative signal checked for every scanned candidate
     * @return immutable bounded page
     */
    List<Credential> listCredentialsPage(PkiId authorityId, Optional<String> after, int limit, java.util.function.Predicate<Credential> include, zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Lists historical issuer generations in ascending issuer-ID order.
     * @param authorityId authoritative logical authority
     * @param after exclusive issuer identifier
     * @param limit maximum rows, 1 through 1001
     * @param include short-lived authorization predicate, never retained
     * @param cancellation cooperative signal checked for every scanned candidate
     * @return immutable bounded page
     */
    List<IssuerGeneration> listIssuerGenerationsPage(PkiId authorityId, Optional<String> after, int limit, java.util.function.Predicate<IssuerGeneration> include, zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Lists status metadata for one authority in ascending status-ID order.
     * @param authorityId authoritative issuer authority
     * @param after exclusive status identifier
     * @param limit maximum rows, 1 through 1001
     * @param include short-lived authorization predicate, never retained
     * @param cancellation cooperative signal checked for every scanned candidate
     * @return immutable bounded page
     */
    List<StatusObject> listStatusObjectsPage(PkiId authorityId, Optional<String> after, int limit, java.util.function.Predicate<StatusObject> include, zeroecho.core.io.CancellationSignal cancellation);

    /**
     * Lists publication metadata in ascending publication-ID order.
     * @param after exclusive publication identifier
     * @param limit maximum rows, 1 through 1001
     * @param include short-lived authorization predicate, never retained
     * @param cancellation cooperative signal checked for every scanned candidate
     * @return immutable bounded page
     */
    List<PublicationRecord> listPublicationsPage(Optional<String> after, int limit, java.util.function.Predicate<PublicationRecord> include, zeroecho.core.io.CancellationSignal cancellation);


    /**
     * Persists one immutable canonical issuer-generation record.
     *
     * @param generation validated issuer generation to store atomically
     */
    void putIssuerGeneration(IssuerGeneration generation);

    /**
     * Retrieves one canonical issuer-generation record.
     *
     * @param issuerId exact issuer-generation identifier
     * @return immutable generation, or empty when absent
     */
    Optional<IssuerGeneration> getIssuerGeneration(PkiId issuerId);

    /**
     * Irreversibly reserves the next CRL number for an authoritative issuer generation.
     * The store resolves the generation and its credential, derives the canonical
     * issuer Name/SPKI scope and validates its permanent logical-authority owner.
     * Full and delta CRLs share one sequence across all generations with that
     * same scope. A different scope has an independent sequence.
     *
     * <p>This operation is thread-safe and successful reservations are linearizable.
     * A number is returned only after its consumption is durably confirmed; it
     * cannot be returned or reused if subsequent signing/publication fails.
     * An uncertain outcome returns no number, may consume a number, and fences
     * the store until recovery. Gaps are therefore permitted and irreversible.
     * Issued numbers range from zero through {@code 2^159 - 1}; exhaustion fails
     * without modifying the counter. Implementations may reject excessive
     * contention after a finite number of compare-and-replace attempts.</p>
     *
     * @param issuerGenerationId exact persisted issuer-generation identifier
     * @return the non-negative, durably reserved number
     * @throws NullPointerException if {@code issuerGenerationId} is {@code null}
     * @throws IllegalStateException if the generation, credential or scope owner
     *         is absent or inconsistent, the counter is exhausted, or bounded
     *         contention prevents reservation
     * @throws zeroecho.pki.api.PkiException if a metadata operation is safely
     *         rejected, for example because bounded capacity is exhausted, or
     *         storage durability cannot be confirmed
     */
    BigInteger reserveCrlNumber(PkiId issuerGenerationId);

    /**
     * Lists issuer generations owned by an exact logical authority.
     *
     * @param authorityId exact logical authority identifier
     * @return immutable generations in store-defined stable order
     */
    List<IssuerGeneration> listIssuerGenerations(PkiId authorityId);

    /**
     * Persists one immutable, already validated issuer chain path.
     *
     * @param path canonical path to store atomically
     */
    void putIssuerChainPath(IssuerChainPath path);

    /**
     * Retrieves one immutable issuer chain path.
     *
     * @param pathId exact chain-path identifier
     * @return immutable path, or empty when absent
     */
    Optional<IssuerChainPath> getIssuerChainPath(PkiId pathId);

    /**
     * Lists explicit paths for an exact issuer generation.
     *
     * @param issuerId exact issuer-generation identifier
     * @return immutable explicit paths in stable order
     */
    List<IssuerChainPath> listIssuerChainPaths(PkiId issuerId);

    /**
     * Persists a credential record.
     *
     * <p>
     * Credentials are typically immutable once issued. Implementations must ensure
     * that storing a credential is atomic and that the record remains retrievable
     * for its entire retention period.
     * </p>
     * <p>X.509 imports require a resolved authoritative issuer (or a verified
     * self-signed root bootstrap). The issuer scope and serial are permanently
     * reserved to the exact certificate content before publication. Reusing a
     * serial with different content or signing ownership is rejected.</p>
     *
     * @param credential credential record (never {@code null})
     * @throws NullPointerException  if {@code credential} is {@code null}
     * @throws IllegalStateException if issuer authority or serial ownership
     *         conflicts, certificate content is invalid, or persistence fails
     */
    void putCredential(Credential credential);

    /**
     * Publishes an X.509 credential from one authoritative signing continuation.
     * The store requires a successful signing result, the stored PUBLISHING
     * continuation and its exact command commitment, and byte-identical signed
     * certificate content. It permanently reserves the issuer scope and serial
     * to that operation/command before the credential becomes visible. Exact
     * replay preserves the original reservation; any competing owner conflicts.
     *
     * @param credential exact immutable credential metadata and store-owned DER
     * @param operationId authoritative signing and continuation identity
     * @param commandCommitment exact versioned stored command commitment
     * @throws NullPointerException if an argument is null
     * @throws IllegalStateException if authority, content or reservation differs,
     *         or persistence fails
     */
    void putCredentialFromSigning(Credential credential, PkiId operationId, String commandCommitment);

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
     * Resolves one exact X.509 credential through the derived issuer-generation
     * and canonical positive serial index. Implementations must validate the
     * returned authoritative credential and must not scan the credential
     * population for a lookup.
     *
     * @param issuerId exact issuer-generation identity
     * @param serial canonical positive X.509 serial
     * @return matching authoritative credential, when issued
     */
    Optional<Credential> getCredentialByIssuerAndSerial(PkiId issuerId, BigInteger serial);

    /**
     * Resolves the exact credential atomically persisted with one issuance intent.
     * Implementations must reject duplicate matches and mismatched command
     * commitments rather than selecting by list order.
     *
     * @param intent exact trusted issuance identity and commitment
     * @return the previously committed credential, when present
     */
    Optional<Credential> getCredentialByIssuanceIntent(IssuanceIntent intent);

    /**
     * Atomically creates the credential-confirmation lifecycle and its pending
     * review projection when absent. An exact replay returns the existing
     * lifecycle; different frozen inputs fail closed.
     *
     * @param initialization exact frozen initialization inputs
     * @return committed initial or identical existing lifecycle
     * @throws IllegalArgumentException if the identity already has different frozen inputs
     * @throws IllegalStateException if the credential is missing, expired, has revocation history,
     *         or persistence cannot be completed safely
     */
    CredentialConfirmationLifecycle initializeCredentialConfirmation(
            CredentialConfirmationInitialization initialization);

    /**
     * Retrieves one authoritative credential-confirmation lifecycle.
     *
     * @param credentialId exact credential identity
     * @return current lifecycle when initialized
     * @throws IllegalStateException if persisted state is corrupt or unavailable
     */
    Optional<CredentialConfirmationLifecycle> getCredentialConfirmation(PkiId credentialId);

    /**
     * Retrieves one authoritative credential-confirmation challenge.
     *
     * @param credentialId exact credential identity
     * @return current challenge when one has been issued
     * @throws IllegalStateException if persisted state is corrupt or unavailable
     */
    Optional<CredentialConfirmationChallenge> getCredentialConfirmationChallenge(PkiId credentialId);

    /**
     * Atomically issues or idempotently resolves one challenge for a pending
     * credential-confirmation lifecycle.
     *
     * <p>A live challenge with identical frozen bindings is returned unchanged.
     * An expired challenge may be replaced only through an exact metadata
     * compare-and-set. Binding mismatches always fail closed.</p>
     *
     * @param issuance exact transient issuance command
     * @return exact committed challenge, which may be an earlier live record
     * @throws IllegalArgumentException if frozen bindings conflict with authoritative state
     * @throws IllegalStateException if the lifecycle is not pending, the credential is unavailable,
     *         or persistence cannot be completed safely
     */
    CredentialConfirmationChallenge issueCredentialConfirmationChallenge(
            CredentialConfirmationChallengeIssuance issuance);

    /**
     * Atomically completes one exact pending lifecycle after consuming its
     * authoritative challenge. The challenge and derived pending-review entry
     * are removed in the same transaction. An exact terminal retry returns the
     * committed confirmed lifecycle.
     *
     * @param proofCas exact pending lifecycle and challenge compare-and-set input
     * @return committed confirmed lifecycle
     * @throws IllegalArgumentException if the expectation conflicts with authoritative state
     * @throws IllegalStateException if the credential is missing, expired, has revocation history,
     *         or persistence cannot be completed safely
     */
    CredentialConfirmationLifecycle completeCredentialConfirmation(CredentialConfirmationProofCas proofCas);

    /**
     * Permanently revokes one still-pending non-public credential strictly after
     * its authoritative confirmation-review boundary.
     *
     * <p>The implementation must read its own authoritative clock and serialize
     * this transition with confirmation and challenge mutations for the same
     * credential. The revocation log is authoritative and is committed before
     * derived review projections and any outstanding challenge are removed.</p>
     *
     * @param command exact permanent revocation command whose reason is
     *        {@link zeroecho.pki.api.revocation.RevocationReason#UNSPECIFIED}
     * @return authoritative permanent revocation record
     * @throws IllegalArgumentException if the command reason is not the fixed reason
     * @throws IllegalStateException if the lifecycle is not eligible or cleanup cannot be established safely
     */
    RevocationRecord revokeOverduePendingCredentialConfirmation(
            RevocationCommand.RevokePermanently command);

    /**
     * Returns one snapshot-consistent bounded keyset page of pending reviews due
     * at or before the exact cutoff. A cursor is exclusive, store-bound, and
     * bound to the cutoff, store, authority, and optional profile supplied when
     * it was issued. The implementation reads only the selected derived index;
     * it does not scan or filter records from another authority or profile.
     *
     * <p>A filesystem metadata implementation performs {@code O(log M + K log M)}
     * metadata point/scan work and returns {@code O(K)} bounded immutable
     * review objects, where {@code M} is its metadata population and {@code K}
     * is the number of returned reviews. Metadata integrity validation adds a
     * constant number of {@code O(log M)} point reads per returned item.</p>
     *
     * @param authorityId mandatory exact issuing-authority scope
     * @param profileId optional exact logical-profile scope
     * @param cutoffInclusive latest review time included in the page
     * @param afterExclusive optional store-issued exclusive cursor
     * @param limit page size from 1 through 4096
     * @return reduced pending reviews in review-time then unsigned strict UTF-8 identity order
     * @throws IllegalArgumentException if the cutoff, cursor, or limit is invalid
     * @throws IllegalStateException if persisted state is corrupt or unavailable
     */
    CredentialConfirmationReviewPage pagePendingCredentialConfirmationReviews(
            PkiId authorityId, Optional<String> profileId, Instant cutoffInclusive,
            Optional<CredentialConfirmationReviewCursor> afterExclusive,
            int limit);

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
     * Returns a bounded page of stored certification requests matching the query.
     *
     * <p>
     * Stores that do not maintain a request listing capability throw
     * {@link UnsupportedOperationException}. Implementations must bound the result
     * to at most {@code maxResults} entries and must not scan without a cap.
     * </p>
     *
     * @param query      request query constraints (never {@code null})
     * @param maxResults positive upper bound on returned entries
     * @return bounded list of matching requests, never {@code null}
     * @throws UnsupportedOperationException if this store cannot list requests
     */
    default List<ParsedCertificationRequest> searchRequests(
            zeroecho.pki.api.request.RequestQuery query, int maxResults) {
        throw new UnsupportedOperationException("This store does not support request search");
    }

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
     * Opens an append-ordered feed captured at the current authoritative log head.
     * Opening rejects a malformed, foreign, or structurally out-of-head position.
     * A same-store, structurally plausible position opens in constant time without
     * scanning the log genesis or materializing the revocation population. Exact
     * authoritative-log continuity and commitment are validated lazily by the
     * first {@link RevocationTransitionFeed#next()} before it yields or advances;
     * an inconsistency is reported as an {@link java.io.IOException}.
     *
     * @param afterExclusive optional exclusive resume position
     * @return closeable feed over the captured append prefix
     * @throws IllegalArgumentException if the position is malformed, foreign, or structurally
     *         outside the captured head
     * @throws IllegalStateException if the authoritative feed cannot be opened safely
     */
    RevocationTransitionFeed openRevocationTransitionFeed(
            Optional<RevocationTransitionFeed.Position> afterExclusive);

    /**
     * Requires an exact authoritative revocation prefix in this store's captured live head.
     * Validation reads a fixed preamble and at most one bounded successor frame;
     * it does not scan history or materialize current states. Genesis requires the
     * canonical initial commitment and boundary. Callers comparing an earlier frozen
     * snapshot must independently enforce that snapshot's source and upper bounds.
     * @param prefix source identity, global revision and commitment to validate
     * @param boundary exclusive byte boundary of the prefix
     * @param cancellation cancellation checked before opening and after validation, including EOF
     * @throws NullPointerException if a required input is null
     * @throws IllegalArgumentException if the prefix is foreign, malformed or outside the captured head
     * @throws IllegalStateException if the store is unavailable
     * @throws java.io.IOException if authoritative continuity, reading or closure fails;
     *         cancellation is propagated as {@link java.io.InterruptedIOException}
     */
    void requireRevocationPrefix(RevocationTransitionFeed.HighWatermark prefix, long boundary,
            zeroecho.core.io.CancellationSignal cancellation) throws java.io.IOException;

    /**
     * Reports whether optional terminal signing and internal-proof evidence is enabled.
     * @return true only when the underlying store maintains the opt-in feed
     */
    default boolean supportsSigningEvidenceFeed() { return false; }

    /**
     * Opens the append-ordered best-effort signing/proof evidence feed. Each marker
     * identifies either the parent operation or its distinct internal proof step.
     * Successful appends survive workflow purge; missing entries can be recovered
     * only while the authoritative workflow remains retained.
     * @param afterSequenceExclusive last projected sequence, or -1 to read from the start
     * @return caller-owned closeable evidence feed
     * @throws UnsupportedOperationException if signing evidence is disabled or unsupported
     * @throws IllegalStateException if the owning store or session is closed or unavailable
     */
    default AuditEvidenceFeed openSigningEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Signing evidence feed is not supported");
    }

    /**
     * Opens the append-ordered issuance success-evidence feed strictly after {@code afterSequenceExclusive}.
     *
     * <p>Each entry is one committed end-entity issuance carrying its co-committed server-derived
     * evidence, enabling a bounded, crash-consistent audit projector. The default throws
     * {@link UnsupportedOperationException} for stores that do not maintain the evidence log.</p>
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable append-ordered evidence feed
     */
    default AuditEvidenceFeed openIssuanceEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Issuance evidence feed is not supported by this store");
    }

    /**
     * Opens the append-ordered status-generation success-evidence feed strictly after
     * {@code afterSequenceExclusive}.
     *
     * <p>Each entry is one committed status object (CRL, delta CRL, or persistent OCSP response) carrying
     * its server-derived generation evidence, enabling a bounded, crash-consistent audit projector.
     * The default throws {@link UnsupportedOperationException} for stores that do not maintain
     * the evidence log.</p>
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable append-ordered evidence feed
     */
    default AuditEvidenceFeed openStatusEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Status evidence feed is not supported by this store");
    }

    /**
     * Opens the append-ordered publication terminal-outcome success-evidence feed strictly after
     * {@code afterSequenceExclusive}.
     *
     * <p>Each entry is one publication that reached a terminal outcome ({@code SUCCEEDED} or
     * {@code TERMINAL_FAILURE}) carrying its server-derived outcome evidence, enabling a bounded,
     * crash-consistent audit projector. The default throws
     * {@link UnsupportedOperationException} for stores that do not maintain the evidence log.</p>
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable append-ordered evidence feed
     */
    default AuditEvidenceFeed openPublicationEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Publication evidence feed is not supported by this store");
    }

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
     * Opens a stable direct-lookup current-state view for finite protocol work.
     *
     * @return closeable snapshot-consistent revocation view
     */
    RevocationView openRevocationView();

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

    /**
     * Retrieves one imported version.
     *
     * @param profileId nonblank logical profile identifier
     * @param profileVersion positive imported version
     * @return immutable imported version, or empty when absent
     */
    Optional<ImportedCertificateProfileVersion> getProfileVersion(String profileId, long profileVersion);

    /**
     * Lists imported versions in ascending version order.
     *
     * @param profileId nonblank logical profile identifier
     * @return immutable finite list ordered by version
     */
    List<ImportedCertificateProfileVersion> listProfileVersions(String profileId);

    /**
     * Atomically activates one imported version.
     *
     * @param profileId nonblank logical profile identifier
     * @param profileVersion positive imported version
     * @return exact newly active profile reference
     */
    CertificateProfileRef activateProfile(String profileId, long profileVersion);

    /**
     * Retrieves the current active reference.
     *
     * @param profileId nonblank logical profile identifier
     * @return current active reference, or empty when none is active
     */
    Optional<CertificateProfileRef> getActiveProfileRef(String profileId);

    /**
     * Resolves the exact active version and validated runtime projection.
     *
     * @param profileId nonblank logical profile identifier
     * @return validated immutable active profile
     */
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

    /**
     * Closes this store and releases all lifecycle-owned resources.
     *
     * <p>After this method returns, implementations must reject new operations.
     * Repeated close calls must follow the implementation's documented idempotence
     * contract. A caller that coordinates multiple resources must preserve the
     * primary close failure and attach later failures as suppressed exceptions.</p>
     *
     * @throws Exception if a lifecycle-owned resource cannot be closed
     */
    @Override
    void close() throws Exception;
}
