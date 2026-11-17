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
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.SSLPeerUnverifiedException;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/**
 * Preserves administrative native transport authentication and its exact safe rejection
 * mapping.
 */
final class AdminTransportAuthentication {
    private static final String TEXT_REQUEST = "request";
    private final PkiServerConfiguration configuration;
    private final PkiServerAuthenticator authenticator;
    /* default */ AdminTransportAuthentication(PkiServerConfiguration configuration, PkiServerAuthenticator authenticator) {
        this.configuration = configuration;
        this.authenticator = authenticator;
    }
    @SuppressWarnings({"PMD.AvoidCatchingGenericException"})
    /* default */ PkiServerAuthenticationResult authenticate(HttpsExchange exchange, String requestId) {
        try {
            Certificate[] peer = exchange.getSSLSession().getPeerCertificates();
            List<X509Certificate> chain = new ArrayList<>();
            for (Certificate certificate : peer) {
                if (!(certificate instanceof X509Certificate x509)) {
                    return new PkiServerAuthenticationResult.Rejected(
                            PkiServerAuthenticationResult.Code.CERTIFICATE_INVALID);
                }
                chain.add(x509);
            }
            return authenticator.authenticate(new PkiServerAuthenticationContext(chain,
                    exchange.getSSLSession().getProtocol(), exchange.getSSLSession().getCipherSuite(),
                    requestId, configuration.realm().realmId(), authenticationHeaders(exchange.getRequestHeaders())));
        } catch (SSLPeerUnverifiedException failure) {
            return new PkiServerAuthenticationResult.Rejected(
                    configuration.authentication().mode(), Optional.empty(), Optional.empty(),
                    PkiServerAuthenticationResult.Code.CERTIFICATE_INVALID);
        } catch (RuntimeException failure) {
            return new PkiServerAuthenticationResult.Rejected(
                    configuration.authentication().mode(), Optional.empty(), Optional.empty(),
                    PkiServerAuthenticationResult.Code.INTERNAL_FAILURE);
        }
    }
    /* default */ Map<String, List<String>> authenticationHeaders(Map<String, List<String>> headers) {
        Set<String> accepted = new java.util.TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        accepted.add(ForwardedClientCertificateParser.RFC_CERTIFICATE_HEADER);
        accepted.add(ForwardedClientCertificateParser.RFC_CHAIN_HEADER);
        accepted.add(ForwardedClientCertificateParser.DIRECT_REJECTED_NGINX_HEADER);
        configuration.authentication().forwardedCertificateHeaderName().ifPresent(accepted::add);
        configuration.authentication().forwardedCertificateChainHeaderName().ifPresent(accepted::add);
        Map<String, List<String>> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (accepted.contains(entry.getKey())) { result.put(entry.getKey(), List.copyOf(entry.getValue())); }
        }
        return Map.copyOf(result);
    }
    /* default */ static Map<String, String> authenticationDetails(String requestId,
            zeroecho.pki.server.AdministrativeAuthenticationMode mode, Optional<String> transport,
            Optional<String> endClient, String classification) {
        Map<String, String> details = new LinkedHashMap<>();
        details.put(TEXT_REQUEST, requestId);
        details.put("mode", mode.name());
        transport.ifPresent(value -> details.put("transportPrincipal", value));
        endClient.ifPresent(value -> details.put("endClientPrincipal", value));
        details.put("classification", classification);
        return Map.copyOf(details);
    }
    /* default */ void requireHeadersBounded(Map<String, List<String>> headers) {
        int bytes = 0;
        for (Map.Entry<String, List<String>> header : headers.entrySet()) {
            bytes = Math.addExact(bytes, header.getKey().getBytes(StandardCharsets.UTF_8).length);
            for (String value : header.getValue()) {
                bytes = Math.addExact(bytes, value.getBytes(StandardCharsets.UTF_8).length);
                if (bytes > configuration.listener().maximumHeaderBytes()) {
                    throw new IllegalArgumentException("Request headers are oversized");
                }
            }
        }
    }
}
