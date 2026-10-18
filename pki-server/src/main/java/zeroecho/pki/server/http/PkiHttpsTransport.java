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
import java.time.Clock;
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
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/**
 * Narrow lifecycle facade hiding the JDK HTTPS listener and bounded execution runtime.
 *
 * <p>The public server lifecycle uses this type only as an internal module boundary;
 * request handlers, queues, permits and provider discovery remain package-private.</p>
 */
@SuppressWarnings("PMD")
public final class PkiHttpsTransport implements AutoCloseable {
    private final HttpsServer listener;
    private final ServerRuntime runtime;

    private PkiHttpsTransport(HttpsServer listener, ServerRuntime runtime) {
        this.listener = listener;
        this.runtime = runtime;
    }

    /**
     * Opens and starts one strictly mutual-TLS listener.
     *
     * @param configuration validated server configuration
     * @param realm shared long-lived realm
     * @param authenticator initialized mTLS authenticator
     * @param clock request-time source
     * @param random correlation identifier source
     * @param loader explicitly scoped TLS-provider loader
     * @param ready readiness predicate owned by the server lifecycle
     * @return started bounded transport
     */
    public static PkiHttpsTransport start(PkiServerConfiguration configuration, ServerRealmContext realm,
            PkiServerAuthenticator authenticator, Clock clock, SecureRandom random, ClassLoader loader,
            BooleanSupplier ready) {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(realm, "realm");
        Objects.requireNonNull(authenticator, "authenticator");
        Objects.requireNonNull(ready, "ready");
        ServerRuntime runtime = null;
        HttpsServer listener = null;
        try {
            SSLContext tls = resolveTls(configuration, loader);
            runtime = new ServerRuntime(configuration.execution());
            listener = HttpsServer.create(configuration.listener().socketAddress(),
                    configuration.execution().transportQueueCapacity());
            listener.setHttpsConfigurator(configurator(tls));
            listener.setExecutor(runtime.transportExecutor());
            listener.createContext("/", new AdminHttpHandler(configuration, realm, authenticator, runtime,
                    clock, new RequestIds(random), ready));
            listener.start();
            return new PkiHttpsTransport(listener, runtime);
        } catch (IOException failure) {
            closePartial(listener, runtime);
            throw new IllegalStateException("HTTPS listener initialization failed");
        } catch (RuntimeException | Error failure) {
            closePartial(listener, runtime);
            throw failure;
        }
    }

    /**
     * Resolves the explicitly selected TLS provider before realm resources are opened.
     *
     * @param configuration validated server configuration
     * @param loader explicitly scoped provider loader
     * @return initialized JSSE context without exposing private-key material
     */
    public static SSLContext resolveTls(PkiServerConfiguration configuration, ClassLoader loader) {
        Objects.requireNonNull(configuration, "configuration");
        return TlsProviders.create(configuration.listener().tlsProvider(), loader);
    }

    /**
     * Starts a listener using a TLS context resolved before realm construction.
     *
     * @param configuration validated server configuration
     * @param realm shared long-lived realm
     * @param authenticator initialized mTLS authenticator
     * @param clock request-time source
     * @param random correlation identifier source
     * @param tls initialized TLS context
     * @param ready readiness predicate
     * @return started bounded transport
     */
    public static PkiHttpsTransport startResolved(PkiServerConfiguration configuration,
            ServerRealmContext realm, PkiServerAuthenticator authenticator, Clock clock, SecureRandom random,
            SSLContext tls, BooleanSupplier ready) {
        Objects.requireNonNull(configuration, "configuration");
        Objects.requireNonNull(tls, "tls");
        ServerRuntime runtime = null;
        HttpsServer listener = null;
        try {
            runtime = new ServerRuntime(configuration.execution());
            listener = HttpsServer.create(configuration.listener().socketAddress(),
                    configuration.execution().transportQueueCapacity());
            listener.setHttpsConfigurator(configurator(tls));
            listener.setExecutor(runtime.transportExecutor());
            listener.createContext("/", new AdminHttpHandler(configuration, realm, authenticator, runtime,
                    clock, new RequestIds(random), ready));
            listener.start();
            return new PkiHttpsTransport(listener, runtime);
        } catch (IOException failure) {
            closePartial(listener, runtime);
            throw new IllegalStateException("HTTPS listener initialization failed");
        } catch (RuntimeException | Error failure) {
            closePartial(listener, runtime);
            throw failure;
        }
    }

    /**
     * Returns the actual bound listener address, including an allocated ephemeral port.
     *
     * @return bound administrative listener address
     */
    public InetSocketAddress address() {
        return listener.getAddress();
    }

    /**
     * Indicates whether operation admission is accepting new requests.
     *
     * @return {@code true} while new requests may be admitted
     */
    public boolean accepting() {
        return runtime.accepting();
    }

    /**
     * Reports the implementation-owned worker marker used to prevent lifecycle
     * self-waits. This is not an application scheduling or authorization signal.
     *
     * @return whether the current thread is owned by a packaged server runtime
     */
    public static boolean currentThreadIsServerWorker() {
        return ServerRuntime.isWorkerThread();
    }

    /** Prevents new operation admission without closing in-flight work. */
    public void quiesce() {
        runtime.quiesce();
    }

    /**
     * Creates the sole process-shutdown thread through the centralized runtime.
     *
     * @param task finite server close action
     * @return unstarted JVM shutdown hook
     */
    public Thread shutdownHook(Runnable task) {
        return ServerRuntime.shutdownHook(Objects.requireNonNull(task, "task"));
    }

    @Override
    public void close() {
        shutdown(Duration.ZERO);
    }

    /**
     * Stops new exchanges, grants admitted exchanges a finite drain period and
     * then closes all bounded executors.
     *
     * @param graceful finite listener drain period
     */
    public void shutdown(Duration graceful) {
        runtime.quiesce();
        int seconds = Math.toIntExact(Math.min(Integer.MAX_VALUE,
                Objects.requireNonNull(graceful, "graceful").toSeconds()));
        listener.stop(seconds);
        runtime.close();
    }

    private static HttpsConfigurator configurator(SSLContext context) {
        return new HttpsConfigurator(context) {
            @Override public void configure(HttpsParameters parameters) {
                SSLParameters secure = context.getDefaultSSLParameters();
                secure.setNeedClientAuth(true);
                parameters.setSSLParameters(secure);
            }
        };
    }

    private static void closePartial(HttpsServer listener, ServerRuntime runtime) {
        if (listener != null) listener.stop(0);
        if (runtime != null) runtime.close();
    }
}
