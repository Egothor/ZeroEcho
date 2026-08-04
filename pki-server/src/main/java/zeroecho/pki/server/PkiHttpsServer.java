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
import java.util.concurrent.atomic.AtomicReference;

import javax.net.ssl.SSLContext;

import zeroecho.pki.application.PkiSessionRuntimeDependencies;
import zeroecho.pki.server.http.MutualTlsAuthenticator;
import zeroecho.pki.server.http.PkiHttpsTransport;
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
    public enum State { NEW, STARTING, READY, QUIESCING, TERMINATED }

    private final PkiServerConfiguration configuration;
    private final ServerRealmContext realm;
    private final PkiServerAuthenticator authenticator;
    private final PkiHttpsTransport transport;
    private final AtomicReference<State> state;

    private PkiHttpsServer(PkiServerConfiguration configuration, ServerRealmContext realm,
            PkiServerAuthenticator authenticator, PkiHttpsTransport transport,
            AtomicReference<State> state) {
        this.configuration = configuration;
        this.realm = realm;
        this.authenticator = authenticator;
        this.transport = transport;
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
        try {
            SSLContext tls = PkiHttpsTransport.resolveTls(exact, loader);
            realm = ServerRealmContext.open(exact.realm(), runtimeDependencies, clock, random);
            realm.auditTransport("SERVER_STARTUP", "system", Map.of("state", "STARTING"));
            authenticator = new MutualTlsAuthenticator(exact.authentication().mappings(), realm::principal, clock);
            ServerRealmContext sharedRealm = realm;
            transport = PkiHttpsTransport.startResolved(exact, sharedRealm, authenticator, clock, random, tls,
                    () -> state.get() == State.READY && sharedRealm.state() == ServerRealmContext.State.OPEN);
            state.set(State.READY);
            realm.auditTransport("SERVER_READY", "system", Map.of("state", "READY"));
            return new PkiHttpsServer(exact, realm, authenticator, transport, state);
        } catch (RuntimeException | Error primary) {
            closePartial(transport, realm, authenticator, state, primary);
            throw primary;
        }
    }

    /** @return current lifecycle state */
    public State state() {
        return state.get();
    }

    /** @return actual bound address, including an allocated ephemeral port */
    public InetSocketAddress address() {
        if (state.get() == State.TERMINATED) throw new IllegalStateException("HTTPS server is terminated");
        return transport.address();
    }

    /** @return the one lifecycle-owned realm context */
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
        if (!state.compareAndSet(State.READY, State.QUIESCING)
                && !state.compareAndSet(State.STARTING, State.QUIESCING)) return;
        Throwable primary = null;
        try {
            realm.auditTransport("SERVER_SHUTDOWN", "system", Map.of("state", "QUIESCING"));
        } catch (Throwable failure) {
            primary = failure;
        }
        transport.quiesce();
        try {
            transport.shutdown(configuration.execution().gracefulShutdown());
        } catch (Throwable failure) {
            primary = suppress(primary, failure);
        }
        primary = close(realm, primary);
        primary = close(authenticator, primary);
        state.set(State.TERMINATED);
        rethrow(primary);
    }

    private static void closePartial(PkiHttpsTransport transport, ServerRealmContext realm,
            PkiServerAuthenticator authenticator, AtomicReference<State> state, Throwable primary) {
        primary = close(transport, primary);
        primary = close(realm, primary);
        close(authenticator, primary);
        state.set(State.TERMINATED);
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

    private static Throwable suppress(Throwable primary, Throwable failure) {
        if (primary == null) return failure;
        if (primary != failure) primary.addSuppressed(failure);
        return primary;
    }

    private static void rethrow(Throwable failure) throws Exception {
        if (failure == null) return;
        if (failure instanceof Exception exception) throw exception;
        if (failure instanceof Error error) throw error;
        throw new IllegalStateException("Server close failed");
    }
}
