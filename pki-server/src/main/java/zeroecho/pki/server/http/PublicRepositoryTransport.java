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
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import zeroecho.pki.server.AdministrativeAuthenticationMode;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;

/** Lifecycle owner for the isolated, optionally enabled public repository listener. */
public final class PublicRepositoryTransport implements AutoCloseable {
    private final HttpServer listener;
    private final ServerRuntime runtime;

    private PublicRepositoryTransport(HttpServer listener, ServerRuntime runtime) {
        this.listener = listener;
        this.runtime = runtime;
    }

    /** Starts one separately bounded public listener over the shared realm. */
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public static PublicRepositoryTransport start(PkiServerConfiguration.PublicListener configuration,
            ServerRealmContext realm, AdministrativeAuthenticator authenticator, Clock clock,
            SecureRandom random, ClassLoader loader, BooleanSupplier ready) {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(realm, "realm");
        Objects.requireNonNull(authenticator, "authenticator");
        ServerRuntime runtime = null;
        HttpServer listener = null;
        try {
            runtime = new ServerRuntime(configuration.execution(), true);
            if (configuration.tlsProvider().isPresent()) {
                SSLContext context = TlsProviders.create(configuration.tlsProvider().orElseThrow(), loader);
                HttpsServer secure = HttpsServer.create(configuration.socketAddress(),
                        configuration.execution().transportQueueCapacity());
                secure.setHttpsConfigurator(configurator(context,
                        configuration.authentication().mode()
                                == AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY));
                listener = secure;
            } else {
                listener = HttpServer.create(configuration.socketAddress(),
                        configuration.execution().transportQueueCapacity());
            }
            listener.setExecutor(runtime.transportExecutor());
            listener.createContext("/", new PublicRepositoryHttpHandler(configuration, realm, authenticator,
                    runtime, clock, new RequestIds(random), ready));
            listener.start();
            return new PublicRepositoryTransport(listener, runtime);
        } catch (IOException failure) {
            closePartial(listener, runtime);
            throw new IllegalStateException("Public repository listener initialization failed", failure);
        } catch (RuntimeException | Error failure) {
            closePartial(listener, runtime);
            throw failure;
        }
    }

    /** @return actual public listener address */
    public InetSocketAddress address() { return listener.getAddress(); }

    /** Prevents new public stream admission. */
    public void quiesce() { runtime.quiesce(); }

    /** Stops the listener and its independent bounded resources. */
    public void shutdown(Duration graceful) {
        runtime.quiesce();
        int seconds = Math.toIntExact(Math.min(Integer.MAX_VALUE,
                Objects.requireNonNull(graceful, "graceful").toSeconds()));
        listener.stop(seconds);
        runtime.close();
    }

    @Override public void close() { shutdown(Duration.ZERO); }

    private static HttpsConfigurator configurator(SSLContext context, boolean proxyMode) {
        return new HttpsConfigurator(context) {
            @Override public void configure(HttpsParameters parameters) {
                SSLParameters secure = context.getDefaultSSLParameters();
                if (proxyMode) {
                    secure.setNeedClientAuth(true);
                } else {
                    secure.setWantClientAuth(true);
                }
                parameters.setSSLParameters(secure);
            }
        };
    }

    private static void closePartial(HttpServer listener, ServerRuntime runtime) {
        if (listener != null) {
            listener.stop(0);
        }
        if (runtime != null) {
            runtime.close();
        }
    }
}
