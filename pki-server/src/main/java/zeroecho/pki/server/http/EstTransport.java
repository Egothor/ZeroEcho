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
package zeroecho.pki.server.http;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Objects;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.est.EstHttpHandler;
import zeroecho.pki.server.est.EstService;

/**
 * Lifecycle owner for the optional EST RFC 7030 HTTPS listener.
 *
 * <p>EST always requires mutual TLS: {@link SSLParameters#setNeedClientAuth(boolean)} is set
 * to {@code true} unconditionally, unlike ACME which may operate behind a trusted proxy.
 * The handler reads the client certificate from the SSL session after the handshake completes.</p>
 *
 * <p>Usage: {@link #start(PkiServerConfiguration.EstListener, ServerRealmContext, SecureRandom, ClassLoader, BooleanSupplier)}
 * returns a fully running transport; call {@link #shutdown(Duration)} or {@link #close()} to stop it.</p>
 *
 * @since 1.0
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ControlStatementBraces" })
public final class EstTransport implements AutoCloseable {

    private final HttpsServer listener;
    private final ServerRuntime protocolRuntime;
    private final EstService service;

    private EstTransport(HttpsServer listener, ServerRuntime protocolRuntime, EstService service) {
        this.listener = listener;
        this.protocolRuntime = protocolRuntime;
        this.service = service;
    }

    /**
     * Starts one EST listener over the lifecycle-owned realm and PKI session.
     *
     * @param configuration validated EST listener configuration
     * @param realm         shared lifecycle-owned realm
     * @param random        cryptographically secure entropy source
     * @param loader        provider service class loader
     * @param ready         readiness predicate checked by request handlers
     * @return started EST listener lifecycle owner
     * @throws IllegalStateException if the listener cannot be initialized
     */
    public static EstTransport start(PkiServerConfiguration.EstListener configuration,
            ServerRealmContext realm, SecureRandom random, ClassLoader loader,
            BooleanSupplier ready) {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(realm, "realm");
        Objects.requireNonNull(random, "random");
        Objects.requireNonNull(loader, "loader");
        Objects.requireNonNull(ready, "ready");

        ServerRuntime protocol = null;
        HttpsServer listener = null;
        try {
            EstService service = new EstService(realm);
            realm.gateway().installEst(service);
            protocol = new ServerRuntime(configuration.execution(), ServerRuntime.Lane.EST);
            SSLContext tls = TlsProviders.create(configuration.tlsProvider(), loader);
            listener = HttpsServer.create(configuration.socketAddress(),
                    configuration.execution().transportQueueCapacity());
            listener.setHttpsConfigurator(mutualTlsConfigurator(tls));
            listener.setExecutor(protocol.transportExecutor());
            listener.createContext("/.well-known/est/",
                    new EstHttpHandler(realm, service, protocol, new RequestIds(random), ready, configuration.maximumBodyBytes(), configuration.execution().maximumDeadline()));
            listener.start();
            return new EstTransport(listener, protocol, service);
        } catch (IOException failure) {
            closePartial(listener, protocol);
            throw new IllegalStateException("EST listener initialization failed", failure);
        } catch (RuntimeException | Error failure) {
            closePartial(listener, protocol);
            throw failure;
        }
    }

    /**
     * Returns the actual listener address, including an allocated ephemeral port.
     *
     * @return bound listener address
     */
    public InetSocketAddress address() {
        return listener.getAddress();
    }

    /**
     * Returns the EST service for administrative endpoint management.
     *
     * @return the EST service holding the endpoint registry
     */
    public EstService service() {
        return service;
    }

    /** Rejects new protocol work. */
    public void quiesce() {
        protocolRuntime.quiesce();
    }

    /**
     * Stops listener admission and the EST lane executors.
     *
     * @param graceful maximum transport drain duration; whole seconds are passed to the listener
     */
    public void shutdown(Duration graceful) {
        quiesce();
        listener.stop(Math.toIntExact(Math.min(Integer.MAX_VALUE, graceful.toSeconds())));
        protocolRuntime.close();
    }

    @Override
    public void close() {
        shutdown(Duration.ZERO);
    }

    /**
     * Configures SSL parameters with mandatory client authentication.
     *
     * <p>Unlike ACME, EST never operates behind a trusted proxy — the client certificate
     * is always required at the TLS layer so that handler code can extract it from the
     * {@code SSLSession} unconditionally.</p>
     */
    private static HttpsConfigurator mutualTlsConfigurator(SSLContext context) {
        return new HttpsConfigurator(context) {
            @Override
            public void configure(HttpsParameters parameters) {
                SSLParameters secure = context.getDefaultSSLParameters();
                secure.setWantClientAuth(false);
                secure.setNeedClientAuth(true);
                parameters.setSSLParameters(secure);
            }
        };
    }

    private static void closePartial(HttpsServer listener, ServerRuntime protocol) {
        if (listener != null) listener.stop(0);
        if (protocol != null) protocol.close();
    }
}
