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
package zeroecho.pki.server;

import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.AdministrativeAuthenticator;
import zeroecho.pki.server.http.AcmeTransport;
import zeroecho.pki.server.http.PkiHttpsTransport;
import zeroecho.pki.server.http.PublicRepositoryTransport;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/**
 * Lifecycle owner for one bounded administrative mutual-TLS HTTPS server.
 *
 * <p>One instance owns one long-lived {@link ServerRealmContext} and therefore
 * one long-lived PKI session. It is thread-safe for lifecycle inspection and
 * idempotent close. HTTP handlers never construct sessions or execute operations
 * outside {@link ServerOperationGateway}.</p>
 */
@SuppressWarnings("PMD")
public final class PkiHttpsServer implements AutoCloseable {
    /** Closed process lifecycle. */
    public enum State {
        /** Constructed but not yet starting. */
        NEW,
        /** Initializing realm and listener resources. */
        STARTING,
        /** Accepting requests. */
        READY,
        /** Rejecting new work while owned resources drain. */
        QUIESCING,
        /** Fully closed; listener addresses and realm access are unavailable. */
        TERMINATED
    }

    private final PkiServerConfiguration configuration;
    private final ServerRealmContext realm;
    private final PkiServerAuthenticator authenticator;
    private final PkiHttpsTransport transport;
    private final Optional<PkiServerAuthenticator> publicAuthenticator;
    private final Optional<PublicRepositoryTransport> publicTransport;
    private final Optional<AcmeTransport> acmeTransport;
    private final Optional<SigningReconciliationWorker> signingReconciliation;
    private final AtomicReference<State> state;
    private final RetryableCloseGate closeGate = new RetryableCloseGate();
    private final AtomicBoolean realmClosed = new AtomicBoolean();
    private final AtomicBoolean authenticatorClosed = new AtomicBoolean();
    private final AtomicBoolean publicAuthenticatorClosed = new AtomicBoolean();

    PkiHttpsServer(PkiServerConfiguration configuration, ServerRealmContext realm,
            PkiServerAuthenticator authenticator, PkiHttpsTransport transport,
            Optional<PkiServerAuthenticator> publicAuthenticator,
            Optional<PublicRepositoryTransport> publicTransport,
            Optional<AcmeTransport> acmeTransport,
            Optional<SigningReconciliationWorker> signingReconciliation,
            AtomicReference<State> state) {
        this.configuration = configuration;
        this.realm = realm;
        this.authenticator = authenticator;
        this.transport = transport;
        this.publicAuthenticator = publicAuthenticator;
        this.publicTransport = publicTransport;
        this.acmeTransport = acmeTransport;
        this.signingReconciliation = signingReconciliation;
        this.state = state;
    }

    /**
     * Starts one production HTTPS server using explicitly configured capabilities.
     *
     * @param configuration validated server configuration
     * @param runtimeDependencies process-local PKI capabilities
     * @return fully ready lifecycle owner
     */
    public static PkiHttpsServer start(PkiServerConfiguration configuration,
            PkiSessionRuntimeDependencies runtimeDependencies) {
        return start(configuration, runtimeDependencies, Clock.systemUTC(), new SecureRandom(),
                Thread.currentThread().getContextClassLoader());
    }

    static PkiHttpsServer start(PkiServerConfiguration configuration,
            PkiSessionRuntimeDependencies runtimeDependencies, Clock clock, SecureRandom random,
            ClassLoader loader) {
        PkiServerConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(runtimeDependencies, "runtimeDependencies");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(random, "random");
        AtomicReference<State> state = new AtomicReference<>(State.NEW);
        state.set(State.STARTING);
        ServerRealmContext realm = null;
        PkiServerAuthenticator authenticator = null;
        PkiHttpsTransport transport = null;
        PkiServerAuthenticator publicAuthenticator = null;
        PublicRepositoryTransport publicTransport = null;
        AcmeTransport acmeTransport = null;
        SigningReconciliationWorker signingReconciliation = null;
        try {
            SSLContext tls = PkiHttpsTransport.resolveTls(exact, loader);
            realm = ServerRealmContext.open(exact.realm(), runtimeDependencies, clock, random);
            realm.auditTransport("SERVER_STARTUP", "system", Map.of("state", "STARTING"));
            if (exact.authentication().mode() == AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY) {
                for (String principalId : exact.authentication().trustedProxyPrincipalIds()) {
                    SecurityPrincipal principal = realm.principal(principalId);
                    if (!principal.enabled() || principal.type() != SecurityPrincipal.Type.SERVICE) {
                        throw new IllegalArgumentException("Trusted proxy principal is unavailable");
                    }
                    realm.gateway().validateForwardingPrincipal(principalId);
                }
            }
            authenticator = AdministrativeAuthenticator.create(exact.authentication(), realm::principal,
                    realm.gateway()::authorizeForwardedIdentity, clock, loader);
            ServerRealmContext sharedRealm = realm;
            transport = PkiHttpsTransport.startResolved(exact, sharedRealm, authenticator, clock, random, tls,
                    () -> state.get() == State.READY && sharedRealm.state() == ServerRealmContext.State.OPEN);
            if (exact.publicListener().isPresent()) {
                PkiServerConfiguration.PublicListener publicConfiguration = exact.publicListener().orElseThrow();
                validateTrustedProxies(publicConfiguration.authentication(), realm);
                AdministrativeAuthenticator resolvedPublicAuthenticator = AdministrativeAuthenticator.create(
                        publicConfiguration.authentication(), realm::principal,
                        realm.gateway()::authorizeForwardedIdentity, clock, loader);
                publicAuthenticator = resolvedPublicAuthenticator;
                publicTransport = PublicRepositoryTransport.start(publicConfiguration, sharedRealm,
                        resolvedPublicAuthenticator, clock, random, loader,
                        () -> state.get() == State.READY && sharedRealm.state() == ServerRealmContext.State.OPEN);
            }
            if (exact.acmeListener().isPresent()) {
                PkiServerConfiguration.AcmeListener acmeConfiguration = exact.acmeListener().orElseThrow();
                if (acmeConfiguration.transportMode()
                        == PkiServerConfiguration.AcmeTransportMode.TRUSTED_REVERSE_PROXY) {
                    for (String principalId : acmeConfiguration.trustedProxyPrincipalIds()) {
                        SecurityPrincipal principal = realm.principal(principalId);
                        if (!principal.enabled() || principal.type() != SecurityPrincipal.Type.SERVICE) {
                            throw new IllegalArgumentException("ACME trusted proxy principal is unavailable");
                        }
                        realm.gateway().validateForwardingPrincipal(principalId);
                    }
                }
                acmeTransport = AcmeTransport.start(acmeConfiguration, sharedRealm, clock, random, loader,
                        () -> state.get() == State.READY && sharedRealm.state() == ServerRealmContext.State.OPEN,
                        sharedRealm::signalReconciliation);
            }
            signingReconciliation = new SigningReconciliationWorker(realm, exact.signingReconciliation(),
                    exact.execution().forcedShutdown(), clock);
            realm.auditTransport("SERVER_READY", "system", Map.of("state", "READY"));
            PkiHttpsServer server = new PkiHttpsServer(exact, realm, authenticator, transport,
                    Optional.ofNullable(publicAuthenticator), Optional.ofNullable(publicTransport),
                    Optional.ofNullable(acmeTransport), Optional.ofNullable(signingReconciliation), state);
            if (signingReconciliation != null) {
                signingReconciliation.start();
            }
            state.set(State.READY);
            return server;
        } catch (RuntimeException | Error primary) {
            closePartial(signingReconciliation, acmeTransport, publicTransport, publicAuthenticator, transport, realm,
                    authenticator, state, primary);
            throw primary;
        }
    }

    /**
     * Returns the current lifecycle state.
     *
     * @return current state
     */
    public State state() {
        return state.get();
    }

    /**
     * Returns the actual bound administrative address, including an allocated ephemeral port.
     *
     * @return administrative listener address
     * @throws IllegalStateException if the server is terminated
     */
    public InetSocketAddress address() {
        if (state.get() == State.TERMINATED) throw new IllegalStateException("HTTPS server is terminated");
        return transport.address();
    }

    /**
     * Returns the actual public listener address when the repository listener is enabled.
     *
     * @return bound public address, or empty when disabled
     * @throws IllegalStateException if the server is terminated
     */
    public Optional<InetSocketAddress> publicAddress() {
        if (state.get() == State.TERMINATED) throw new IllegalStateException("HTTPS server is terminated");
        return publicTransport.map(PublicRepositoryTransport::address);
    }

    /**
     * Returns the actual ACME listener address when enabled.
     *
     * @return bound ACME address, or empty when disabled
     * @throws IllegalStateException if the server is terminated
     */
    public Optional<InetSocketAddress> acmeAddress() {
        if (state.get() == State.TERMINATED) throw new IllegalStateException("HTTPS server is terminated");
        return acmeTransport.map(AcmeTransport::address);
    }

    /**
     * Returns the one lifecycle-owned realm context.
     *
     * @return the open realm context
     * @throws IllegalStateException unless the server is ready
     */
    public ServerRealmContext realm() {
        if (state.get() != State.READY) throw new IllegalStateException("HTTPS server is not ready");
        return realm;
    }

    /**
     * Installs the sole finite process-shutdown bridge for the packaged launcher.
     * Tests and embedded integrations may instead close the server directly.
     */
    public void installShutdownHook() {
        Runtime.getRuntime().addShutdownHook(transport.shutdownHook(() -> {
            try {
                close();
            } catch (Exception ignored) {
                // A shutdown hook has no safe caller to receive close failure details.
            }
        }));
    }

    /**
     * Quiesces admission, terminates the listener and bounded executors, then
     * closes realm and authentication resources. Repeated calls are harmless.
     */
    @Override
    public void close() throws Exception {
        closeFromServerWorker(PkiHttpsTransport.currentThreadIsServerWorker());
    }

    void closeFromServerWorker(boolean workerThread) throws Exception {
        closeGate.close(workerThread, this::quiesceForClose, this::closeAttempt);
    }

    private void quiesceForClose() {
        state.compareAndSet(State.READY, State.QUIESCING);
        state.compareAndSet(State.STARTING, State.QUIESCING);
        signingReconciliation.ifPresent(SigningReconciliationWorker::stopScheduling);
        transport.quiesce();
        publicTransport.ifPresent(PublicRepositoryTransport::quiesce);
        acmeTransport.ifPresent(AcmeTransport::quiesce);
    }

    private Throwable closeAttempt() {
        quiesceForClose();
        Throwable primary = null;
        if (!realmClosed.get()) {
            try {
                realm.auditTransport("SERVER_SHUTDOWN", "system", Map.of("state", "QUIESCING"));
            } catch (Throwable failure) {
                primary = failure;
            }
        }
        try {
            if (acmeTransport.isPresent()) {
                acmeTransport.orElseThrow().shutdown(configuration.acmeListener().orElseThrow()
                        .execution().gracefulShutdown());
            }
        } catch (Throwable failure) {
            primary = suppress(primary, failure);
        }
        try {
            if (publicTransport.isPresent()) {
                publicTransport.orElseThrow().shutdown(configuration.publicListener().orElseThrow()
                        .execution().gracefulShutdown());
            }
        } catch (Throwable failure) {
            primary = suppress(primary, failure);
        }
        try {
            transport.shutdown(configuration.execution().gracefulShutdown());
        } catch (Throwable failure) {
            primary = suppress(primary, failure);
        }
        try {
            if (signingReconciliation.isPresent()) {
                signingReconciliation.orElseThrow().awaitStopped();
            }
        } catch (Throwable failure) {
            return preferFailure(failure, primary);
        }
        if (primary != null) {
            return primary;
        }
        primary = closeOnce(realm, realmClosed, null);
        if (primary != null) {
            return primary;
        }
        if (publicAuthenticator.isPresent()) {
            primary = closeOnce(publicAuthenticator.orElseThrow(), publicAuthenticatorClosed, null);
        }
        primary = closeOnce(authenticator, authenticatorClosed, primary);
        if (primary == null) {
            state.set(State.TERMINATED);
        }
        return primary;
    }

    private static void closePartial(SigningReconciliationWorker signingReconciliation, AcmeTransport acmeTransport,
            PublicRepositoryTransport publicTransport,
            PkiServerAuthenticator publicAuthenticator, PkiHttpsTransport transport, ServerRealmContext realm,
            PkiServerAuthenticator authenticator, AtomicReference<State> state, Throwable primary) {
        if (signingReconciliation != null) {
            try {
                signingReconciliation.close();
            } catch (Throwable failure) {
                if (primary != failure) primary.addSuppressed(failure);
                close(acmeTransport, primary);
                close(publicTransport, primary);
                close(transport, primary);
                return;
            }
        }
        primary = close(acmeTransport, primary);
        primary = close(publicTransport, primary);
        primary = close(publicAuthenticator, primary);
        primary = close(transport, primary);
        primary = close(authenticator, primary);
        close(realm, primary);
        state.set(State.TERMINATED);
    }

    private static void validateTrustedProxies(PkiServerConfiguration.Authentication authentication,
            ServerRealmContext realm) {
        if (authentication.mode() != AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY) return;
        for (String principalId : authentication.trustedProxyPrincipalIds()) {
            SecurityPrincipal principal = realm.principal(principalId);
            if (!principal.enabled() || principal.type() != SecurityPrincipal.Type.SERVICE) {
                throw new IllegalArgumentException("Trusted proxy principal is unavailable");
            }
            realm.gateway().validateForwardingPrincipal(principalId);
        }
    }

    private static Throwable close(AutoCloseable resource, Throwable primary) {
        if (resource == null) return primary;
        try {
            resource.close();
        } catch (Throwable failure) {
            return suppress(primary, failure);
        }
        return primary;
    }

    private static Throwable closeOnce(AutoCloseable resource, AtomicBoolean closed, Throwable primary) {
        if (closed.get()) return primary;
        try {
            resource.close();
            closed.set(true);
        } catch (Throwable failure) {
            return suppress(primary, failure);
        }
        return primary;
    }

    private static Throwable suppress(Throwable primary, Throwable failure) {
        if (primary == null) return failure;
        if (primary != failure) primary.addSuppressed(failure);
        return primary;
    }

    private static Throwable preferFailure(Throwable failure, Throwable prior) {
        if (prior != null && prior != failure) {
            failure.addSuppressed(prior);
        }
        return failure;
    }
}
