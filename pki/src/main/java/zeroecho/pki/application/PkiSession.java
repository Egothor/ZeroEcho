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
package zeroecho.pki.application;

import java.time.Clock;
import java.util.Objects;
import java.util.Optional;

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.PkiId;

/**
 * Lifecycle-owned synchronous PKI backend session.
 *
 * <p>A session is constructed from one validated immutable configuration and is
 * suitable for one CLI plan or for the complete lifetime of a future server.
 * It creates no scheduler, thread or executor. Implementations reject service
 * access after close.</p>
 */
public interface PkiSession extends AutoCloseable {

    /**
     * Opens a production session.
     *
     * @param configuration validated immutable configuration
     * @return opened session
     * @throws IllegalArgumentException if configuration is invalid
     * @throws RuntimeException if resource construction fails
     */
    static PkiSession open(PkiSessionConfiguration configuration) {
        return DefaultPkiSession.open(configuration);
    }

    /**
     * Opens a production session with explicit process-local security capabilities.
     *
     * @param configuration validated immutable provider configuration
     * @param dependencies process-local key-access capabilities
     * @return opened lifecycle-owned session
     */
    static PkiSession open(PkiSessionConfiguration configuration, PkiSessionRuntimeDependencies dependencies) {
        return DefaultPkiSession.open(configuration, dependencies);
    }

    /**
     * Opens a production session with explicit process-local capabilities and a
     * lifecycle clock shared by every time-dependent backend service.
     *
     * @param configuration validated immutable provider configuration
     * @param dependencies process-local key-access capabilities
     * @param clock authoritative session clock
     * @return opened lifecycle-owned session
     */
    static PkiSession open(PkiSessionConfiguration configuration, PkiSessionRuntimeDependencies dependencies,
            Clock clock) {
        return DefaultPkiSession.open(configuration, dependencies, clock);
    }

    /**
     * Returns the profile lifecycle service.
     *
     * @return session-owned profile service
     */
    ProfileService profiles();

    /**
     * Returns the credential-confirmation facade owned by this session.
     *
     * @return session-owned confirmation service
     * @throws IllegalStateException if the session is closed
     */
    CredentialConfirmationService confirmations();

    /**
     * Returns the revocation service.
     *
     * @return session-owned revocation service
     */
    RevocationService revocations();

    /**
     * Returns the configured CA service.
     *
     * @return service, or empty for a read-only session
     */
    default Optional<CaService> authorities() {
        return Optional.empty();
    }

    /**
     * Returns the certification-request service.
     *
     * @return service, or empty when X.509 is unavailable
     */
    default Optional<CertificationRequestService> requests() {
        return Optional.empty();
    }

    /**
     * Returns the issuance service.
     *
     * @return service, or empty when signing is unavailable
     */
    default Optional<IssuanceService> issuance() {
        return Optional.empty();
    }

    /**
     * Returns the status-object service.
     *
     * @return service, or empty when signing is unavailable
     */
    default Optional<StatusObjectService> statusObjects() {
        return Optional.empty();
    }

    /**
     * Returns the confined OCSP responder service.
     *
     * @return service, or empty when signing is unavailable
     */
    default Optional<OcspResponseService> ocsp() { return Optional.empty(); }

    /**
     * Returns the publication service.
     *
     * @return service, or empty when no destination is enabled
     */
    default Optional<PublicationService> publications() {
        return Optional.empty();
    }

    /**
     * Returns the immutable active X.509 algorithm-binding registry.
     *
     * @return session-owned immutable registry, available to read-only sessions
     */
    X509AlgorithmBindingRegistry algorithmBindings();

    /**
     * Returns the read-only authoritative identifier resolver used to cross-check
     * realm and authority scopes before protected operations.
     *
     * @return session-owned resource-scope resolver
     */
    default PkiResourceScopeResolver resourceScopes() {
        return new PkiResourceScopeResolver() {
            @Override public Optional<CredentialScope> credentialScope(PkiId credentialId) {
                return Optional.empty();
            }
            @Override public Optional<PkiId> statusObjectAuthority(PkiId statusObjectId) { return Optional.empty(); }
            @Override public Optional<PkiId> publicationAuthority(PkiId publicationId) { return Optional.empty(); }
        };
    }

    /**
     * Returns the typed operation executor.
     *
     * @return shared session-owned executor
     */
    PkiOperationExecutor operations();

    /**
     * Opens the append-ordered issuance success-evidence feed strictly after {@code afterSequenceExclusive}.
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable append-ordered evidence feed for the issuance audit projector (Task 8a)
     */
    default zeroecho.pki.spi.store.AuditEvidenceFeed openIssuanceEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Issuance evidence feed is not supported by this session");
    }

    /**
     * Opens the append-ordered status-generation success-evidence feed strictly after
     * {@code afterSequenceExclusive}.
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable append-ordered evidence feed for the status audit projector (Task 8a)
     */
    default zeroecho.pki.spi.store.AuditEvidenceFeed openStatusEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Status evidence feed is not supported by this session");
    }

    /**
     * Opens the append-ordered publication terminal-outcome success-evidence feed strictly after
     * {@code afterSequenceExclusive}.
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable append-ordered evidence feed for the publication audit projector (Task 8a)
     */
    default zeroecho.pki.spi.store.AuditEvidenceFeed openPublicationEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Publication evidence feed is not supported by this session");
    }

    /**
     * Opens the append-ordered signing terminal-outcome success-evidence feed strictly after
     * {@code afterSequenceExclusive}.
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable append-ordered evidence feed for the signing audit projector (Task 8a)
     */
    default zeroecho.pki.spi.store.AuditEvidenceFeed openSigningEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Signing evidence feed is not supported by this session");
    }

    /**
     * Reports whether the underlying store maintains the signing terminal-outcome evidence log.
     *
     * @return {@code true} only when signing key-usage audit is enabled; default {@code false}
     */
    default boolean supportsSigningEvidenceFeed() {
        return false;
    }

    /**
     * Returns the typed durable outcome of one outer signing operation.
     *
     * @param operationId private durable operation identifier
     * @return completed, pending, or failed outcome; unknown identifiers are
     *         returned as {@link PkiOperationFailure#NOT_FOUND}
     */
    default PkiOperationOutcome signingOperation(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        return new PkiOperationOutcome.Failed("signing.operation", PkiOperationFailure.NOT_FOUND,
                "OBJECT_NOT_FOUND");
    }

    /**
     * Resolves one durable signing-backed domain operation by its trusted
     * idempotency identity, without scanning the signing population.
     * @param correlationId nonblank trusted idempotency identity
     * @return completed, pending, or not-found outcome
     */
    default PkiOperationOutcome signingOperation(String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            throw new IllegalArgumentException("correlationId must not be blank");
        }
        return new PkiOperationOutcome.Failed("signing.operation",
                PkiOperationFailure.NOT_FOUND, "OBJECT_NOT_FOUND");
    }

    /**
     * Returns the private operation id atomically indexed by a domain correlation.
     * @param correlationId nonblank trusted idempotency identity
     * @return exact private operation identifier, or empty when absent
     */
    default Optional<PkiId> signingOperationId(String correlationId) {
        if (correlationId == null || correlationId.isBlank()) {
            throw new IllegalArgumentException("correlationId must not be blank");
        }
        return Optional.empty();
    }

    /**
     * Returns the exact original authorization projection for a durable signing operation.
     *
     * <p>The projection is recovered from the authoritative domain continuation
     * and contains no requester identity. Callers must authorize the current
     * principal against it before exposing operation status.</p>
     *
     * @param operationId private durable operation identifier
     * @return immutable authorization projection, or empty when unavailable
     */
    default Optional<SigningOperationAuthorization> signingOperationAuthorization(PkiId operationId) {
        Objects.requireNonNull(operationId, "operationId");
        return Optional.empty();
    }

    /**
     * Resolves and validates the operation indexed by one exact frozen issuance.
     *
     * @param binding expected authority, issuer, path, profile, and issuance commitment
     * @return the matching private operation identifier, when present
     */
    default Optional<PkiId> issuanceSigningOperationId(SigningIssuanceBinding binding) {
        Objects.requireNonNull(binding, "binding");
        return Optional.empty();
    }

    /**
     * Returns an issuance operation only after validating its complete frozen binding.
     *
     * @param operationId private durable operation identifier
     * @param binding expected authority, issuer, path, profile, and issuance commitment
     * @return completed, pending, or failed operation outcome
     */
    default PkiOperationOutcome issuanceSigningOperation(PkiId operationId,
            SigningIssuanceBinding binding) {
        Objects.requireNonNull(operationId, "operationId");
        Objects.requireNonNull(binding, "binding");
        return new PkiOperationOutcome.Failed("signing.operation", PkiOperationFailure.NOT_FOUND,
                "OBJECT_NOT_FOUND");
    }

    /**
     * Returns the authoritative repository facade.
     *
     * @return session-owned read-only repository
     */
    PkiRepository repository();

    /**
     * Performs one synchronous, bounded signing-recovery pass.
     *
     * <p>The session creates no scheduler. Callers own invocation cadence and must
     * carry the preceding result's complete {@link SigningReconciliationContinuation},
     * including its cursor, frozen high-watermark, wrap boundary, and phase. Use
     * {@link SigningReconciliationRequest#continueFrom} to replace pass bounds
     * without separating that continuation state. A session without signing
     * returns an empty, end-reached result.</p>
     *
     * @param request validated pass bounds and cancellation
     * @return aggregate safe pass result
     * @throws IllegalStateException if the session is closed
     */
    SigningReconciliationResult reconcileSigning(SigningReconciliationRequest request);

    /**
     * Registers one best-effort reconciliation wake listener for provider
     * advisories. The returned handle unregisters it. Polling remains authoritative.
     *
     * @param listener non-blocking wake signal
     * @return registration handle, or an inert handle when signing is disabled
     */
    default AutoCloseable registerSigningAdvisoryWake(Runnable listener) {
        Objects.requireNonNull(listener, "listener");
        return () -> { };
    }

    /**
     * Returns bounded signing runtime metrics.
     *
     * @return snapshot, or empty when signing is disabled
     */
    default Optional<SigningExecutionMetrics> signingExecutionMetrics() {
        return Optional.empty();
    }

    /**
     * Closes services and backend resources in reverse construction order.
     * Repeated calls are harmless; primary and suppressed failures are preserved.
     *
     * @throws Exception if resource closure fails
     */
    @Override
    void close() throws Exception;
}
