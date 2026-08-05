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

import zeroecho.pki.api.CaService;
import zeroecho.pki.api.CertificationRequestService;
import zeroecho.pki.api.IssuanceService;
import zeroecho.pki.api.PublicationService;
import zeroecho.pki.api.ProfileService;
import zeroecho.pki.api.RevocationService;
import zeroecho.pki.api.StatusObjectService;
import zeroecho.pki.api.algorithm.X509AlgorithmBindingRegistry;

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

    /** @return profile lifecycle service owned by this session */
    ProfileService profiles();

    /** @return revocation service owned by this session */
    RevocationService revocations();

    /** @return configured CA service, or empty for a read-only session */
    default Optional<CaService> authorities() {
        return Optional.empty();
    }

    /** @return configured certification-request service, or empty when X.509 is unavailable */
    default Optional<CertificationRequestService> requests() {
        return Optional.empty();
    }

    /** @return configured issuance service, or empty when signing is unavailable */
    default Optional<IssuanceService> issuance() {
        return Optional.empty();
    }

    /** @return configured status-object service, or empty when signing is unavailable */
    default Optional<StatusObjectService> statusObjects() {
        return Optional.empty();
    }

    /** @return confined OCSP responder service, or empty when signing is unavailable */
    default Optional<OcspResponseService> ocsp() { return Optional.empty(); }

    /** @return configured publication service, or empty when no destination is enabled */
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
            @Override public Optional<zeroecho.pki.api.PkiId> credentialAuthority(
                    zeroecho.pki.api.PkiId credentialId) { return Optional.empty(); }
            @Override public Optional<zeroecho.pki.api.PkiId> statusObjectAuthority(
                    zeroecho.pki.api.PkiId statusObjectId) { return Optional.empty(); }
            @Override public Optional<zeroecho.pki.api.PkiId> publicationAuthority(
                    zeroecho.pki.api.PkiId publicationId) { return Optional.empty(); }
        };
    }

    /** @return shared typed operation executor owned by this session */
    PkiOperationExecutor operations();

    /** @return read-only authoritative repository facade owned by this session */
    PkiRepository repository();

    /**
     * Closes services and backend resources in reverse construction order.
     * Repeated calls are harmless; primary and suppressed failures are preserved.
     *
     * @throws Exception if resource closure fails
     */
    @Override
    void close() throws Exception;
}
