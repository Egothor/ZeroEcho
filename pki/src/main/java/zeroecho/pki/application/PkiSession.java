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
import java.util.Optional;

import zeroecho.pki.api.BackupService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.SigningService;
import zeroecho.pki.api.SemanticSigningService;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;
import zeroecho.pki.api.confirmation.CredentialConfirmationService;
import zeroecho.pki.api.PkiId;

/**
 * Lifecycle-owned synchronous PKI backend session.
 *
 * <p>A session is constructed from one validated immutable configuration and is
 * suitable for one CLI plan or for the complete lifetime of a future server.
 * Unconfigured sessions create no signing threads. A configured signing service
 * opened through {@code open} owns a bounded reactor for the session lifetime.
 * {@code openLocal} executes signing on the caller thread without constructing a
 * reactor. Local calls are sequential, including closing only after the current
 * command returns. Implementations reject service access after close.</p>
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
     * Opens a standalone caller-thread session with a declared local root operator.
     * @param configuration immutable local configuration
     * @param dependencies process-local key-access and audit capabilities
     * @return exclusive lifecycle-owned session without a signing reactor
     * @throws IllegalArgumentException if provider configuration is invalid
     * @throws RuntimeException if resource construction fails
     */
    static PkiSession openLocal(LocalPkiSessionConfiguration configuration, PkiSessionRuntimeDependencies dependencies) {
        return openLocal(configuration, dependencies, Clock.systemUTC());
    }

    /**
     * Opens a standalone session with one authoritative lifecycle clock.
     * @param configuration immutable local configuration
     * @param dependencies process-local key-access and audit capabilities
     * @param clock authoritative session clock
     * @return exclusive lifecycle-owned session without a signing reactor
     * @throws IllegalArgumentException if provider configuration is invalid
     * @throws RuntimeException if resource construction fails
     */
    static PkiSession openLocal(LocalPkiSessionConfiguration configuration, PkiSessionRuntimeDependencies dependencies,
            Clock clock) {
        return DefaultPkiSession.openLocal(configuration, dependencies, clock);
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
     * Returns the certification-request service.
     *
     * @return service, or empty when X.509 is unavailable
     */
    default Optional<CertificationRequestService> requests() {
        return Optional.empty();
    }

    /**
     * Returns the publication service.
     *
     * @return service, or empty when no destination is enabled
     */
    default Optional<PublicationService> publications() {
        return Optional.empty();
    }

    /**
     * Returns the configured durable signing service, if enabled.
     *
     * @return session-owned signing service, or empty when unconfigured
     */
    default Optional<SigningService> signing() {
        return Optional.empty();
    }

    /**
     * Returns the semantic lifecycle facade sharing the configured signing runtime.
     *
     * @return session-owned semantic service, or empty when signing is unconfigured
     * @throws IllegalStateException if the session is closed
     */
    default Optional<SemanticSigningService> semanticSigning() {
        return Optional.empty();
    }

    /**
     * Returns shared signing-command preparation and completed-result projection.
     *
     * @return borrowed service, or empty when signing is unconfigured
     * @throws IllegalStateException if the session is closed
     */
    default Optional<PkiSigningCommands> signingCommands() {
        return Optional.empty();
    }

    /**
     * Returns the borrowed sequential caller-thread signing executor.
     * @return local executor, or empty in reactive sessions and when signing is unconfigured
     * @throws IllegalStateException if the session is closed
     */
    default Optional<LocalSigningExecutor> localSigning() {
        return Optional.empty();
    }

    /**
     * Returns the borrowed durable status-scheduling coordinator when signing and store support are configured.
     * @return scheduling service, or empty when unavailable
     */
    default Optional<zeroecho.pki.api.schedule.StatusScheduleCoordinator> statusSchedules() {
        return Optional.empty();
    }

    /**
     * Returns OCSP response generation over the configured signing reactor.
     *
     * @return borrowed session service, or empty when signing is unconfigured
     * @throws IllegalStateException if the session is closed
     */
    default Optional<OcspResponseService> ocsp() {
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
    default zeroecho.pki.spi.store.AuditEvidenceFeed openSigningEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Signing evidence feed is not supported");
    }

    /**
     * Opens the append-ordered issuance success-evidence feed strictly after
     * {@code afterSequenceExclusive}.
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return caller-owned closeable evidence feed for the issuance audit projector
     * @throws IllegalStateException if the session is closed
     * @throws UnsupportedOperationException if the session or store does not support the feed
     */
    default zeroecho.pki.spi.store.AuditEvidenceFeed openIssuanceEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Issuance evidence feed is not supported by this session");
    }

    /**
     * Opens the append-ordered status-generation success-evidence feed strictly after
     * {@code afterSequenceExclusive}.
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return caller-owned closeable evidence feed for the status-generation audit projector
     * @throws IllegalStateException if the session is closed
     * @throws UnsupportedOperationException if the session or store does not support the feed
     */
    default zeroecho.pki.spi.store.AuditEvidenceFeed openStatusEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Status evidence feed is not supported by this session");
    }

    /**
     * Opens the append-ordered publication terminal-outcome success-evidence feed strictly after
     * {@code afterSequenceExclusive}.
     *
     * @param afterSequenceExclusive last projected sequence, or {@code -1} to read from the start
     * @return closeable append-ordered evidence feed for the publication audit projector
     */
    default zeroecho.pki.spi.store.AuditEvidenceFeed openPublicationEvidenceFeed(long afterSequenceExclusive) {
        throw new UnsupportedOperationException("Publication evidence feed is not supported by this session");
    }

    /**
     * Returns the authoritative repository facade.
     *
     * @return session-owned read-only repository
     */
    PkiRepository repository();

    /**
     * Returns the session's authoritative inventory, revocation and time resolver.
     * Callers must supply credentials read from the authoritative repository and
     * reuse one evaluation across the candidates of one trust decision. The
     * resolver and retained evaluations reject use after session closure.
     * @return lifecycle-owned resolver; never a metadata-only status fallback
     * @throws IllegalStateException when the session is not open
     */
    zeroecho.pki.api.credential.EffectiveCredentialStatusResolver credentialStatuses();

    /**
     * Returns the backup service when the underlying store supports backup operations.
     *
     * <p>Sessions backed by stores that do not support backup return {@link Optional#empty()}.
     * Callers must check before invoking any backup or restore operation.</p>
     *
     * @return backup service, or empty when the backing store does not support backup
     */
    default Optional<BackupService> backup() { return Optional.empty(); }

    /**
     * Closes services and backend resources in reverse construction order.
     * Repeated calls are harmless; primary and suppressed failures are preserved.
     *
     * @throws Exception if resource closure fails
     */
    @Override
    void close() throws Exception;
}
