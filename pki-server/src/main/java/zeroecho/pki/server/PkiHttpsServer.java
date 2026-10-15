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
import zeroecho.pki.server.http.CmpTransport;
import zeroecho.pki.server.http.EstTransport;
import zeroecho.pki.server.http.PkiHttpsTransport;
import zeroecho.pki.server.http.PublicRepositoryTransport;
import zeroecho.pki.server.http.ScepTransport;
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
    private final Optional<EstTransport> estTransport;
    private final Optional<ScepTransport> scepTransport;
    private final Optional<CmpTransport> cmpTransport;
    private final Optional<AuditProjectionWorker> auditProjection;
    private final StatusScheduleWorker statusSchedule;
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
            Optional<EstTransport> estTransport,
            Optional<ScepTransport> scepTransport,
            Optional<CmpTransport> cmpTransport,
            Optional<AuditProjectionWorker> auditProjection,
            StatusScheduleWorker statusSchedule,
            AtomicReference<State> state) {
        this.configuration = configuration;
        this.realm = realm;
        this.authenticator = authenticator;
        this.transport = transport;
        this.publicAuthenticator = publicAuthenticator;
        this.publicTransport = publicTransport;
        this.acmeTransport = acmeTransport;
        this.estTransport = estTransport;
        this.scepTransport = scepTransport;
        this.cmpTransport = cmpTransport;
        this.auditProjection = auditProjection;
        this.statusSchedule = statusSchedule;
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
        return start(configuration, runtimeDependencies, clock, random, loader, Optional.empty());
    }

    /**
     * Starts the server with optional, explicitly budgeted backup transfer.
     * @param configuration validated schema-8 server settings
     * @param runtimeDependencies process-local PKI capabilities
     * @param transfer optional separately validated transfer settings
     * @return fully ready server lifecycle owner
     */
    public static PkiHttpsServer start(PkiServerConfiguration configuration,
            PkiSessionRuntimeDependencies runtimeDependencies, Optional<BackupTransferConfiguration> transfer) {
        return start(configuration, runtimeDependencies, Clock.systemUTC(), new SecureRandom(),
                Thread.currentThread().getContextClassLoader(), Objects.requireNonNull(transfer));
    }

    static PkiHttpsServer start(PkiServerConfiguration configuration,
            PkiSessionRuntimeDependencies runtimeDependencies, Clock clock, SecureRandom random,
            ClassLoader loader, Optional<BackupTransferConfiguration> transfer) {
        return start(configuration, runtimeDependencies, clock, random, loader, transfer, Optional.empty());
    }

    /**
     * Starts a server with explicit independent backup and enrollment capabilities.
     * @param configuration schema-8 server settings
     * @param runtimeDependencies process-local unlock and runtime capabilities
     * @param transfer optional backup transfer budgets
     * @param enrollment mandatory companion for enabled enrollment listeners
     * @return fully ready server owning all opened resources
     */
    public static PkiHttpsServer start(PkiServerConfiguration configuration,
            PkiSessionRuntimeDependencies runtimeDependencies, Optional<BackupTransferConfiguration> transfer,
            Optional<zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration> enrollment) {
        return start(configuration, runtimeDependencies, Clock.systemUTC(), new SecureRandom(),
                Thread.currentThread().getContextClassLoader(), transfer, enrollment);
    }

    static PkiHttpsServer start(PkiServerConfiguration configuration,
            PkiSessionRuntimeDependencies runtimeDependencies, Clock clock, SecureRandom random,
            ClassLoader loader, Optional<BackupTransferConfiguration> transfer,
            Optional<zeroecho.pki.server.enrollment.EnrollmentRuntimeConfiguration> enrollment) {
        PkiServerConfiguration exact = Objects.requireNonNull(configuration, "configuration");
        zeroecho.pki.server.enrollment.EnrollmentRuntime.validateConfiguration(exact, enrollment, transfer);
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
        EstTransport estTransport = null;
        ScepTransport scepTransport = null;
        CmpTransport cmpTransport = null;
        AuditProjectionWorker auditProjection = null;
        StatusScheduleWorker statusSchedule = null;
        AtomicReference<ServerRealmContext> metricsRealm = new AtomicReference<>();
        AtomicReference<StatusScheduleWorker> metricsWorker = new AtomicReference<>();
        AtomicBoolean schedulingConfigured = new AtomicBoolean();
        try {
            SSLContext tls = PkiHttpsTransport.resolveTls(exact, loader);
            zeroecho.pki.application.DashboardLiveSource liveSource = new zeroecho.pki.application.DashboardLiveSource() {
                @Override public long approvalPendingTotal() { return metricsRealm.get().pendingApprovalCount(clock.instant()); }
                @Override public long auditProjectionFailureTotal() { return metricsRealm.get().auditProjectionFailureTotal(); }
                @Override public long jvmHeapUsedBytes() {
                    return java.lang.management.ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
                }
                @Override public long adminRequestsTotal() { return metricsRealm.get().adminRequestsTotal(); }
                @Override public Map<String, Metric> snapshot() {
                    Map<String, Metric> result = new java.util.LinkedHashMap<>(zeroecho.pki.application.DashboardLiveSource.super.snapshot());
                    if (schedulingConfigured.get()) {
                        result.put("statusScheduleFailureTotal", zeroecho.pki.application.DashboardLiveSource.collect(
                                () -> metricsRealm.get().scheduleFailureTotal()));
                        result.put("statusScheduleWorkerRunning", zeroecho.pki.application.DashboardLiveSource.collect(
                                () -> metricsWorker.get().isRunning() ? 1L : 0L));
                    }
                    return Map.copyOf(result);
                }
            };
            PkiSessionRuntimeDependencies resolvedDependencies = runtimeDependencies.withDashboardLiveSource(liveSource);
            realm = ServerRealmContext.open(exact.realm(), resolvedDependencies, clock, random);
            if (transfer.isPresent()) {
                try { realm.installBackupTransfer(transfer.orElseThrow(), clock, random); }
                catch (java.io.IOException failure) { throw new IllegalStateException("Backup transfer startup failed", failure); }
            }
            if (enrollment.isPresent()) {
                realm.installEnrollmentRuntime(enrollment.orElseThrow(), resolvedDependencies, clock);
                realm.installEnrollmentCoordinator(exact.authentication(), clock);
            }
            metricsRealm.set(realm);
            schedulingConfigured.set(realm.session().statusSchedules().isPresent());
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
            if (exact.estListener().isPresent()) {
                estTransport = EstTransport.start(exact.estListener().orElseThrow(), sharedRealm, random, loader,
                        () -> state.get() == State.READY && sharedRealm.state() == ServerRealmContext.State.OPEN);
            }
            if (exact.scepListener().isPresent()) {
                scepTransport = ScepTransport.start(exact.scepListener().orElseThrow(), sharedRealm, random, loader,
                        () -> state.get() == State.READY && sharedRealm.state() == ServerRealmContext.State.OPEN);
            }
            if (exact.cmpListener().isPresent()) {
                cmpTransport = CmpTransport.start(exact.cmpListener().orElseThrow(), sharedRealm, random, loader,
                        () -> state.get() == State.READY && sharedRealm.state() == ServerRealmContext.State.OPEN);
            }
            auditProjection = new AuditProjectionWorker(realm, exact.auditProjection(),
                    exact.execution().forcedShutdown(), clock);
            statusSchedule = new StatusScheduleWorker(
                    new StatusScheduleExecutor(realm.session().statusSchedules(), clock, realm::recordScheduleFailure),
                    exact.execution().forcedShutdown(), clock, realm::recordScheduleFailure);
            metricsWorker.set(statusSchedule);
            realm.auditTransport("SERVER_READY", "system", Map.of("state", "READY"));
            PkiHttpsServer server = new PkiHttpsServer(exact, realm, authenticator, transport,
                    Optional.ofNullable(publicAuthenticator), Optional.ofNullable(publicTransport),
                    Optional.ofNullable(acmeTransport), Optional.ofNullable(estTransport),
                    Optional.ofNullable(scepTransport), Optional.ofNullable(cmpTransport),
                    Optional.ofNullable(auditProjection), statusSchedule, state);
            if (auditProjection != null) {
                auditProjection.start();
            }
            statusSchedule.start();
            state.set(State.READY);
            return server;
        } catch (RuntimeException | Error primary) {
            closePartial(auditProjection, statusSchedule, cmpTransport, scepTransport, estTransport, acmeTransport,
                    publicTransport, publicAuthenticator, transport, realm, authenticator, state, primary);
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
     * Returns the actual EST listener address when enabled.
     *
     * @return bound EST address, or empty when disabled
     * @throws IllegalStateException if the server is terminated
     */
    public Optional<InetSocketAddress> estAddress() {
        if (state.get() == State.TERMINATED) throw new IllegalStateException("HTTPS server is terminated");
        return estTransport.map(EstTransport::address);
    }

    /**
     * Returns the actual SCEP listener address when enabled.
     *
     * @return bound SCEP address, or empty when disabled
     * @throws IllegalStateException if the server is terminated
     */
    public Optional<InetSocketAddress> scepAddress() {
        if (state.get() == State.TERMINATED) throw new IllegalStateException("HTTPS server is terminated");
        return scepTransport.map(ScepTransport::address);
    }

    /**
     * Returns the actual CMP listener address when enabled.
     *
     * @return bound CMP address, or empty when disabled
     * @throws IllegalStateException if the server is terminated
     */
    public Optional<InetSocketAddress> cmpAddress() {
        if (state.get() == State.TERMINATED) throw new IllegalStateException("HTTPS server is terminated");
        return cmpTransport.map(CmpTransport::address);
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
        auditProjection.ifPresent(AuditProjectionWorker::stopScheduling);
        statusSchedule.stopScheduling();
        transport.quiesce();
        publicTransport.ifPresent(PublicRepositoryTransport::quiesce);
        acmeTransport.ifPresent(AcmeTransport::quiesce);
        estTransport.ifPresent(EstTransport::quiesce);
        scepTransport.ifPresent(ScepTransport::quiesce);
        cmpTransport.ifPresent(CmpTransport::quiesce);
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
            if (estTransport.isPresent()) {
                estTransport.orElseThrow().shutdown(configuration.estListener().orElseThrow()
                        .execution().gracefulShutdown());
            }
        } catch (Throwable failure) {
            primary = suppress(primary, failure);
        }
        try {
            if (scepTransport.isPresent()) {
                scepTransport.orElseThrow().shutdown(configuration.scepListener().orElseThrow()
                        .execution().gracefulShutdown());
            }
        } catch (Throwable failure) {
            primary = suppress(primary, failure);
        }
        try {
            if (cmpTransport.isPresent()) {
                cmpTransport.orElseThrow().shutdown(configuration.cmpListener().orElseThrow()
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
            if (auditProjection.isPresent()) {
                auditProjection.orElseThrow().awaitStopped();
            }
        } catch (Throwable failure) {
            return preferFailure(failure, primary);
        }
        try {
            statusSchedule.awaitStopped();
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

    private static void closePartial(AuditProjectionWorker auditProjection, StatusScheduleWorker statusSchedule,
            CmpTransport cmpTransport, ScepTransport scepTransport, EstTransport estTransport,
            AcmeTransport acmeTransport, PublicRepositoryTransport publicTransport,
            PkiServerAuthenticator publicAuthenticator, PkiHttpsTransport transport, ServerRealmContext realm,
            PkiServerAuthenticator authenticator, AtomicReference<State> state, Throwable primary) {
        if (auditProjection != null) {
            try {
                auditProjection.close();
            } catch (Throwable failure) {
                if (primary != failure) primary.addSuppressed(failure);
                close(statusSchedule, primary);
                close(cmpTransport, primary);
                close(scepTransport, primary);
                close(estTransport, primary);
                close(acmeTransport, primary);
                close(publicTransport, primary);
                close(transport, primary);
                return;
            }
        }
        if (statusSchedule != null) {
            try {
                statusSchedule.close();
            } catch (Throwable failure) {
                if (primary != failure) primary.addSuppressed(failure);
                close(cmpTransport, primary);
                close(scepTransport, primary);
                close(estTransport, primary);
                close(acmeTransport, primary);
                close(publicTransport, primary);
                close(transport, primary);
                return;
            }
        }
        primary = close(cmpTransport, primary);
        primary = close(scepTransport, primary);
        primary = close(estTransport, primary);
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
