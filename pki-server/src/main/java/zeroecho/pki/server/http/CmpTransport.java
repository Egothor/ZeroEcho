/* *****************************************************************************
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
import zeroecho.pki.server.cmp.CmpService;

/**
 * Lifecycle owner for the optional CMP RFC 4210/9480 HTTPS listener (RFC 6712 transport).
 *
 * <p>CMP uses signature or shared-secret protection inside the PKIMessage itself;
 * the TLS layer provides confidentiality only. Client authentication at the TLS
 * layer is therefore not required.</p>
 *
 * <p>Usage: {@link #start} returns a fully running transport; call {@link #shutdown}
 * or {@link #close()} to stop it.</p>
 *
 * @since 1.0
 */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ControlStatementBraces" })
public final class CmpTransport implements AutoCloseable {

    private final HttpsServer listener;
    private final ServerRuntime protocolRuntime;
    private final CmpService service;

    private CmpTransport(HttpsServer listener, ServerRuntime protocolRuntime, CmpService service) {
        this.listener = listener;
        this.protocolRuntime = protocolRuntime;
        this.service = service;
    }

    /**
     * Starts one CMP listener over the lifecycle-owned realm and PKI session.
     *
     * @param configuration validated CMP listener configuration
     * @param realm         shared lifecycle-owned realm
     * @param random        cryptographically secure entropy source
     * @param loader        provider service class loader
     * @param ready         readiness predicate checked by request handlers
     * @return started CMP listener lifecycle owner
     * @throws IllegalStateException if the listener cannot be initialized
     */
    public static CmpTransport start(PkiServerConfiguration.CmpListener configuration,
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
            CmpService service = new CmpService(realm);
            realm.gateway().installCmp(service);
            protocol = new ServerRuntime(configuration.execution(), ServerRuntime.Lane.CMP);
            SSLContext tls = TlsProviders.create(configuration.tlsProvider(), loader);
            listener = HttpsServer.create(configuration.socketAddress(),
                    configuration.execution().transportQueueCapacity());
            listener.setHttpsConfigurator(tlsConfigurator(tls));
            listener.setExecutor(protocol.transportExecutor());
            listener.createContext("/pkix/",
                    new CmpHttpHandler(configuration, realm, service, protocol,
                            new RequestIds(random), ready));
            listener.start();
            return new CmpTransport(listener, protocol, service);
        } catch (IOException failure) {
            closePartial(listener, protocol);
            throw new IllegalStateException("CMP listener initialization failed", failure);
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
     * Returns the CMP service for administrative endpoint management.
     *
     * @return the CMP service holding the endpoint registry
     */
    public CmpService service() {
        return service;
    }

    /** Rejects new protocol work. */
    public void quiesce() {
        protocolRuntime.quiesce();
    }

    /**
     * Stops listener admission and the CMP lane executors.
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

    private static HttpsConfigurator tlsConfigurator(SSLContext context) {
        return new HttpsConfigurator(context) {
            @Override
            public void configure(HttpsParameters parameters) {
                SSLParameters secure = context.getDefaultSSLParameters();
                secure.setNeedClientAuth(false);
                secure.setWantClientAuth(false);
                parameters.setSSLParameters(secure);
            }
        };
    }

    private static void closePartial(HttpsServer listener, ServerRuntime protocol) {
        if (listener != null) listener.stop(0);
        if (protocol != null) protocol.close();
    }
}
