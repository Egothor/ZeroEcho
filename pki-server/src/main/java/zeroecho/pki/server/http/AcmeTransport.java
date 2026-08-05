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
 *******************************************************************************/
package zeroecho.pki.server.http;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.function.BooleanSupplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.acme.AcmeNonceService;
import zeroecho.pki.server.acme.AcmeProviders;
import zeroecho.pki.server.acme.AcmeService;
import zeroecho.pki.server.spi.AcmeChallengeProvider;
import zeroecho.pki.server.spi.AcmeExternalAccountBindingProvider;
import zeroecho.pki.spi.ProviderConfig;

/** Lifecycle owner for the isolated optional ACME HTTPS listener. */
@SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ControlStatementBraces" })
public final class AcmeTransport implements AutoCloseable {
    private final HttpsServer listener;
    private final ServerRuntime protocolRuntime;
    private final ServerRuntime.ChallengeRuntime validationRuntime;

    private AcmeTransport(HttpsServer listener, ServerRuntime protocolRuntime,
            ServerRuntime.ChallengeRuntime validationRuntime) {
        this.listener = listener;
        this.protocolRuntime = protocolRuntime;
        this.validationRuntime = validationRuntime;
    }

    /** Starts one ACME listener over the lifecycle-owned realm and PKI session. */
    public static AcmeTransport start(PkiServerConfiguration.AcmeListener configuration,
            ServerRealmContext realm, Clock clock, SecureRandom random, ClassLoader loader,
            BooleanSupplier ready) {
        Objects.requireNonNull(configuration, "configuration");
        ServerRuntime protocol = null;
        ServerRuntime.ChallengeRuntime validation = null;
        HttpsServer listener = null;
        try {
            Map<String, AcmeChallengeProvider> providers = AcmeProviders.challenges(
                    configuration.challengeProviders(), loader);
            Map<String, ProviderConfig> providerConfigurations = configuration.challengeProviders().stream()
                    .collect(java.util.stream.Collectors.toUnmodifiableMap(ProviderConfig::backendId, value -> value));
            Map<String, AcmeExternalAccountBindingProvider> eabProviders = AcmeProviders.eab(
                    configuration.eabProviders(), loader);
            Map<String, ProviderConfig> eabConfigurations = configuration.eabProviders().stream()
                    .collect(java.util.stream.Collectors.toUnmodifiableMap(ProviderConfig::backendId, value -> value));
            AcmeService service = new AcmeService(realm, clock, random, providers, providerConfigurations,
                    eabProviders, eabConfigurations);
            realm.gateway().installAcme(service);
            AcmeNonceService nonces = new AcmeNonceService(configuration.listenerId(),
                    configuration.nonceLifetime(), configuration.maximumOutstandingNonces(), clock, random);
            protocol = new ServerRuntime(configuration.execution(), ServerRuntime.Lane.ACME);
            validation = new ServerRuntime.ChallengeRuntime(configuration.validationExecution());
            SSLContext tls = TlsProviders.create(configuration.tlsProvider(), loader);
            listener = HttpsServer.create(configuration.socketAddress(),
                    configuration.execution().transportQueueCapacity());
            boolean proxy = configuration.transportMode()
                    == PkiServerConfiguration.AcmeTransportMode.TRUSTED_REVERSE_PROXY;
            listener.setHttpsConfigurator(configurator(tls, proxy));
            listener.setExecutor(protocol.transportExecutor());
            listener.createContext("/", new AcmeHttpHandler(configuration, realm, service, nonces,
                    protocol, validation, clock, new RequestIds(random), ready));
            listener.start();
            return new AcmeTransport(listener, protocol, validation);
        } catch (IOException failure) {
            closePartial(listener, validation, protocol);
            throw new IllegalStateException("ACME listener initialization failed", failure);
        } catch (RuntimeException | Error failure) {
            closePartial(listener, validation, protocol);
            throw failure;
        }
    }

    /** @return actual listener address, including an allocated ephemeral port */
    public InetSocketAddress address() { return listener.getAddress(); }

    /** Rejects new protocol and validation work. */
    public void quiesce() { protocolRuntime.quiesce(); validationRuntime.quiesce(); }

    /** Stops listener admission and all separately bounded ACME lanes. */
    public void shutdown(Duration graceful) {
        quiesce();
        listener.stop(Math.toIntExact(Math.min(Integer.MAX_VALUE, graceful.toSeconds())));
        validationRuntime.close();
        protocolRuntime.close();
    }

    @Override public void close() { shutdown(Duration.ZERO); }

    private static HttpsConfigurator configurator(SSLContext context, boolean proxy) {
        return new HttpsConfigurator(context) {
            @Override public void configure(HttpsParameters parameters) {
                SSLParameters secure = context.getDefaultSSLParameters();
                secure.setNeedClientAuth(proxy);
                secure.setWantClientAuth(false);
                parameters.setSSLParameters(secure);
            }
        };
    }

    private static void closePartial(HttpsServer listener, ServerRuntime.ChallengeRuntime validation,
            ServerRuntime protocol) {
        if (listener != null) listener.stop(0);
        if (validation != null) validation.close();
        if (protocol != null) protocol.close();
    }
}
