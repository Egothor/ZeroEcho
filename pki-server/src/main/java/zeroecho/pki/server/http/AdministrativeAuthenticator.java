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

import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.function.Function;

import javax.net.ssl.X509TrustManager;

import zeroecho.pki.server.AdministrativeAuthenticationMode;
import zeroecho.pki.server.AuthorizationEngine;
import zeroecho.pki.server.PkiServerConfiguration;
import zeroecho.pki.server.SecurityPrincipal;
import zeroecho.pki.server.spi.PkiServerAuthenticationContext;
import zeroecho.pki.server.spi.PkiServerAuthenticationResult;
import zeroecho.pki.server.spi.PkiServerAuthenticator;

/**
 * Composes direct mutual-TLS authentication or separately authenticated proxy
 * transport with independently validated forwarded end-client identity.
 *
 * <p>Direct proof of possession comes from the ZeroEcho TLS handshake. In proxy
 * mode proof of possession for the forwarded key is attested by the mutually
 * authenticated, explicitly authorized proxy; parsing a certificate does not by
 * itself prove possession.</p>
 */
@SuppressWarnings("PMD.AvoidCatchingGenericException")
public final class AdministrativeAuthenticator implements PkiServerAuthenticator {
    private static final String CLIENT_AUTH_EKU = "1.3.6.1.5.5.7.3.2";
    private static final String ANY_EKU = "2.5.29.37.0";
    private final PkiServerConfiguration.Authentication configuration;
    private final MutualTlsAuthenticator transportMapper;
    private final MutualTlsAuthenticator endClientMapper;
    private final X509TrustManager forwardedTrust;
    private final BiFunction<String, String, AuthorizationEngine.Decision> forwardingAuthorization;

    private AdministrativeAuthenticator(PkiServerConfiguration.Authentication configuration,
            MutualTlsAuthenticator transportMapper, MutualTlsAuthenticator endClientMapper,
            X509TrustManager forwardedTrust,
            BiFunction<String, String, AuthorizationEngine.Decision> forwardingAuthorization) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.transportMapper = Objects.requireNonNull(transportMapper, "transportMapper");
        this.endClientMapper = Objects.requireNonNull(endClientMapper, "endClientMapper");
        this.forwardedTrust = forwardedTrust;
        this.forwardingAuthorization = Objects.requireNonNull(forwardingAuthorization,
                "forwardingAuthorization");
    }

    /**
     * Creates the configured authentication composition before listener startup.
     *
     * @param configuration strict mode-specific configuration
     * @param principalResolver durable enabled-state resolver
     * @param forwardingAuthorization default-deny proxy forwarding authorization
     * @param clock certificate validity clock
     * @param loader explicitly scoped provider loader
     * @return immutable request authenticator
     */
    public static AdministrativeAuthenticator create(PkiServerConfiguration.Authentication configuration,
            Function<String, SecurityPrincipal> principalResolver,
            BiFunction<String, String, AuthorizationEngine.Decision> forwardingAuthorization,
            Clock clock, ClassLoader loader) {
        PkiServerConfiguration.Authentication exact = Objects.requireNonNull(configuration, "configuration");
        if (exact.mode() == AdministrativeAuthenticationMode.DIRECT_MTLS) {
            MutualTlsAuthenticator direct = new MutualTlsAuthenticator(exact.directClientMappings(),
                    principalResolver, clock);
            return new AdministrativeAuthenticator(exact, direct, direct, null, forwardingAuthorization);
        }
        MutualTlsAuthenticator transport = new MutualTlsAuthenticator(exact.proxyTransportMappings(),
                principalResolver, clock);
        MutualTlsAuthenticator endClient = new MutualTlsAuthenticator(exact.forwardedClientMappings(),
                principalResolver, clock);
        X509TrustManager trust = ClientTrustProviders.create(exact.administrativeClientTrust().orElseThrow(), loader);
        return new AdministrativeAuthenticator(exact, transport, endClient, trust, forwardingAuthorization);
    }

    @Override
    public PkiServerAuthenticationResult authenticate(PkiServerAuthenticationContext context) {
        Objects.requireNonNull(context, "context");
        if (configuration.mode() == AdministrativeAuthenticationMode.DIRECT_MTLS) {
            return direct(context);
        }
        return proxy(context);
    }

    /**
     * Authenticates only the backend transport for an anonymous public request.
     * This method is valid solely in trusted-proxy mode and never manufactures an
     * end-client principal.
     *
     * @param context backend TLS peer context without operation data
     * @return authorized trusted-proxy principal, or empty on any safe failure
     */
    public Optional<String> authenticatePublicProxyTransport(PkiServerAuthenticationContext context) {
        Objects.requireNonNull(context, "context");
        if (configuration.mode() != AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY) {
            return Optional.empty();
        }
        PkiServerAuthenticationResult result = transportMapper.authenticate(context);
        if (!(result instanceof PkiServerAuthenticationResult.Authenticated authenticated)) {
            return Optional.empty();
        }
        String principalId = authenticated.endClientPrincipalId();
        if (!configuration.trustedProxyPrincipalIds().contains(principalId)) {
            return Optional.empty();
        }
        try {
            return forwardingAuthorization.apply(principalId, context.requestId()).allowed()
                    ? Optional.of(principalId) : Optional.empty();
        } catch (RuntimeException unavailable) {
            return Optional.empty();
        }
    }

    private PkiServerAuthenticationResult direct(PkiServerAuthenticationContext context) {
        if (ForwardedClientCertificateParser.containsForwardedIdentity(context.requestHeaders())) {
            return rejected(AdministrativeAuthenticationMode.DIRECT_MTLS, Optional.empty(),
                    PkiServerAuthenticationResult.Code.FORWARDED_IDENTITY_FORBIDDEN);
        }
        PkiServerAuthenticationResult result = transportMapper.authenticate(context);
        if (result instanceof PkiServerAuthenticationResult.Authenticated authenticated) {
            return new PkiServerAuthenticationResult.Authenticated(AdministrativeAuthenticationMode.DIRECT_MTLS,
                    Optional.empty(), authenticated.endClientPrincipalId(), authenticated.credentialEvidence());
        }
        return result;
    }

    private PkiServerAuthenticationResult proxy(PkiServerAuthenticationContext context) {
        PkiServerAuthenticationResult transportResult = transportMapper.authenticate(context);
        if (!(transportResult instanceof PkiServerAuthenticationResult.Authenticated transport)) {
            PkiServerAuthenticationResult.Rejected rejection =
                    (PkiServerAuthenticationResult.Rejected) transportResult;
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY,
                    rejection.endClientPrincipalId(), rejection.code());
        }
        String transportId = transport.endClientPrincipalId();
        Optional<String> resolvedTransport = Optional.of(transportId);
        if (!configuration.trustedProxyPrincipalIds().contains(transportId)) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.PROXY_NOT_TRUSTED);
        }
        AuthorizationEngine.Decision forwarding;
        try {
            forwarding = forwardingAuthorization.apply(transportId, context.requestId());
        } catch (RuntimeException unavailable) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.INTERNAL_FAILURE);
        }
        if (!forwarding.allowed()) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.FORWARDING_NOT_AUTHORIZED);
        }
        List<X509Certificate> forwarded;
        try {
            forwarded = ForwardedClientCertificateParser.parse(configuration, context.requestHeaders());
        } catch (IllegalArgumentException invalid) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.FORWARDED_IDENTITY_INVALID);
        } catch (RuntimeException unavailable) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.INTERNAL_FAILURE);
        }
        try {
            if (sameCredential(context.peerCertificates().getFirst(), forwarded.getFirst())) {
                return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                        PkiServerAuthenticationResult.Code.IDENTITY_COLLISION);
            }
        } catch (CertificateException invalid) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.FORWARDED_IDENTITY_INVALID);
        } catch (RuntimeException unavailable) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.INTERNAL_FAILURE);
        }
        try {
            validateUsage(forwarded.getFirst());
        } catch (CertificateException invalidUsage) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.CLIENT_USAGE_REJECTED);
        } catch (RuntimeException unavailable) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.INTERNAL_FAILURE);
        }
        try {
            forwardedTrust.checkClientTrusted(forwarded.toArray(X509Certificate[]::new),
                    forwarded.getFirst().getPublicKey().getAlgorithm());
        } catch (CertificateException untrusted) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.CLIENT_TRUST_REJECTED);
        } catch (RuntimeException unavailable) {
            return rejected(AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    PkiServerAuthenticationResult.Code.INTERNAL_FAILURE);
        }
        return mapForwarded(context, forwarded, transport);
    }

    private PkiServerAuthenticationResult mapForwarded(PkiServerAuthenticationContext context,
            List<X509Certificate> forwarded, PkiServerAuthenticationResult.Authenticated transport) {
        String transportId = transport.endClientPrincipalId();
        Optional<String> resolvedTransport = Optional.of(transportId);
        PkiServerAuthenticationContext forwardedContext = new PkiServerAuthenticationContext(forwarded,
                context.protocol(), context.cipherSuite(), context.requestId(), context.realmId(), Map.of());
        PkiServerAuthenticationResult endResult = endClientMapper.authenticate(forwardedContext);
        if (!(endResult instanceof PkiServerAuthenticationResult.Authenticated endClient)) {
            PkiServerAuthenticationResult.Rejected rejection =
                    (PkiServerAuthenticationResult.Rejected) endResult;
            return new PkiServerAuthenticationResult.Rejected(
                    AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    rejection.endClientPrincipalId(), rejection.code());
        }
        String endId = endClient.endClientPrincipalId();
        if (transportId.equals(endId)
                || transport.credentialEvidence().isPresent() && endClient.credentialEvidence().isPresent()
                && transport.credentialEvidence().orElseThrow().sameCredential(endClient.credentialEvidence().orElseThrow())) {
            return new PkiServerAuthenticationResult.Rejected(
                    AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport,
                    Optional.of(endId), PkiServerAuthenticationResult.Code.IDENTITY_COLLISION);
        }
        return new PkiServerAuthenticationResult.Authenticated(
                AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY, resolvedTransport, endId,
                endClient.credentialEvidence());
    }

    private static boolean sameCredential(X509Certificate transport, X509Certificate forwarded)
            throws CertificateException {
        return MessageDigest.isEqual(transport.getEncoded(), forwarded.getEncoded())
                || MessageDigest.isEqual(transport.getPublicKey().getEncoded(),
                        forwarded.getPublicKey().getEncoded());
    }

    private static void validateUsage(X509Certificate certificate) throws CertificateException {
        boolean[] usage = certificate.getKeyUsage();
        if (usage != null && (usage.length == 0 || !usage[0])) {
            throw new CertificateException("Administrative client key usage is invalid");
        }
        List<String> extended = certificate.getExtendedKeyUsage();
        if (extended != null && !extended.contains(CLIENT_AUTH_EKU) && !extended.contains(ANY_EKU)) {
            throw new CertificateException("Administrative client extended key usage is invalid");
        }
    }

    private static PkiServerAuthenticationResult rejected(AdministrativeAuthenticationMode mode,
            Optional<String> transport, PkiServerAuthenticationResult.Code code) {
        return new PkiServerAuthenticationResult.Rejected(mode, transport, Optional.empty(), code);
    }
}
