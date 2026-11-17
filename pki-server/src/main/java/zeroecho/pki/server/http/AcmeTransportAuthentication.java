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

import com.sun.net.httpserver.HttpsExchange;

import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.ServerRealmContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.SSLPeerUnverifiedException;

/**
 * Authenticates direct and proxied HTTPS requests to the ACME listener.
 */
final class AcmeTransportAuthentication {
    private final PkiServerConfiguration.AcmeListener configuration;
    private final ServerRealmContext realm;
    private final MutualTlsAuthenticator proxyAuthenticator;

    /* default */ AcmeTransportAuthentication(
            PkiServerConfiguration.AcmeListener configuration,
            ServerRealmContext realm,
            Clock clock) {
        this.configuration = configuration;
        this.realm = realm;
        this.proxyAuthenticator =
                new MutualTlsAuthenticator(
                        configuration.proxyTransportMappings(), realm::principal, clock);
    }

    // Native transport authentication must retain its existing safe rejection for peer/runtime
    // failures.
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    /* default */ boolean authenticate(HttpsExchange exchange, String requestId) {
        if (configuration.transportMode() == PkiServerConfiguration.AcmeTransportMode.DIRECT_TLS) {
            return true;
        }
        try {
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate certificate : exchange.getSSLSession().getPeerCertificates()) {
                if (!(certificate instanceof X509Certificate x509)) {
                    return false;
                }
                chain.add(x509);
            }
            PkiServerAuthenticationResult result =
                    proxyAuthenticator.authenticate(
                            new PkiServerAuthenticationContext(
                                    chain,
                                    exchange.getSSLSession().getProtocol(),
                                    exchange.getSSLSession().getCipherSuite(),
                                    requestId,
                                    realm.configuration().realmId()));
            if (!(result instanceof PkiServerAuthenticationResult.Authenticated authenticated)
                    || !configuration
                            .trustedProxyPrincipalIds()
                            .contains(authenticated.endClientPrincipalId())) {
                return false;
            }
            return realm.gateway()
                    .authorizeForwardedIdentity(authenticated.endClientPrincipalId(), requestId)
                    .allowed();
        } catch (SSLPeerUnverifiedException | RuntimeException failure) {
            return false;
        }
    }
}
