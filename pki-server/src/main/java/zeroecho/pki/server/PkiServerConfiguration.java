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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import zeroecho.pki.spi.ProviderConfig;

/**
 * Strict immutable configuration for one administrative HTTPS server instance.
 *
 * <p>The record owns no secret values. Provider properties may contain paths and
 * names of external environment-variable references and therefore must never be
 * rendered or logged. One instance belongs to exactly one realm and creates one
 * long-lived {@link ServerRealmContext}.</p>
 *
 * @param version server schema version
 * @param serverName safe bounded operational name
 * @param realm exact realm configuration
 * @param listener HTTPS listener policy
 * @param authentication strict client-certificate mappings
 * @param execution bounded execution and shutdown policy
 * @param runtime process-local capability references
 */
@SuppressWarnings("PMD")
public record PkiServerConfiguration(int version, String serverName, ServerRealmConfiguration realm,
        Listener listener, Authentication authentication, Execution execution, RuntimeCapabilities runtime) {

    /** Current server configuration schema. */
    public static final int CURRENT_VERSION = 2;

    /** Validates all security-sensitive fields before resource allocation. */
    public PkiServerConfiguration {
        if (version != CURRENT_VERSION) throw new IllegalArgumentException("Unsupported server schema version");
        Permission.requireBounded(serverName, 128, "server name");
        Objects.requireNonNull(realm, "realm");
        Objects.requireNonNull(listener, "listener");
        Objects.requireNonNull(authentication, "authentication");
        Objects.requireNonNull(execution, "execution");
        Objects.requireNonNull(runtime, "runtime");
        if (!listener.clientCertificateRequired()) {
            throw new IllegalArgumentException("Administrative HTTPS requires client certificates");
        }
    }

    /**
     * HTTPS listener configuration.
     *
     * @param address parsed canonical literal bind address
     * @param port TCP port, where zero requests an ephemeral test port
     * @param tlsProvider explicitly selected TLS material provider
     * @param clientCertificateRequired must be {@code true}
     * @param maximumHeaderBytes bounded aggregate decoded header bytes
     * @param maximumBodyBytes bounded request body bytes
     */
    public record Listener(InetAddress address, int port, ProviderConfig tlsProvider,
            boolean clientCertificateRequired, int maximumHeaderBytes, int maximumBodyBytes) {
        /** Validates listener bounds and explicit TLS selection. */
        public Listener {
            Objects.requireNonNull(address, "address");
            if (port < 0 || port > 65_535) throw new IllegalArgumentException("Listener port is invalid");
            Objects.requireNonNull(tlsProvider, "tlsProvider");
            if (maximumHeaderBytes < 1_024 || maximumHeaderBytes > 1_048_576) {
                throw new IllegalArgumentException("Header bound is invalid");
            }
            if (maximumBodyBytes < 1_024 || maximumBodyBytes > 16_777_216) {
                throw new IllegalArgumentException("Body bound is invalid");
            }
        }

        /** @return exact socket address without DNS resolution */
        public InetSocketAddress socketAddress() {
            return new InetSocketAddress(address, port);
        }
    }

    /**
     * Strict mode-separated administrative client-certificate authentication.
     *
     * @param mode exact deployment mode
     * @param directClientMappings direct TLS end-client mappings
     * @param proxyTransportMappings backend TLS proxy mappings
     * @param forwardedClientMappings externally authenticated end-client mappings
     * @param trustedProxyPrincipalIds explicitly admitted infrastructure principals
     * @param forwardedCertificateFormat selected forwarding representation
     * @param forwardedCertificateHeaderName exact leaf header name
     * @param forwardedCertificateChainHeaderName optional exact chain header name
     * @param administrativeClientTrust independent forwarded-client trust provider
     * @param maximumForwardedCertificateBytes maximum decoded leaf size
     * @param maximumForwardedChainBytes maximum aggregate decoded chain size
     */
    public record Authentication(AdministrativeAuthenticationMode mode,
            List<ClientCertificateMapping> directClientMappings,
            List<ClientCertificateMapping> proxyTransportMappings,
            List<ClientCertificateMapping> forwardedClientMappings,
            Set<String> trustedProxyPrincipalIds,
            Optional<ForwardedCertificateFormat> forwardedCertificateFormat,
            Optional<String> forwardedCertificateHeaderName,
            Optional<String> forwardedCertificateChainHeaderName,
            Optional<ProviderConfig> administrativeClientTrust,
            int maximumForwardedCertificateBytes, int maximumForwardedChainBytes) {
        /** Validates strict mode separation, mappings, headers, and technical bounds. */
        public Authentication {
            Objects.requireNonNull(mode, "mode");
            directClientMappings = mappings(directClientMappings, "direct client");
            proxyTransportMappings = mappings(proxyTransportMappings, "proxy transport");
            forwardedClientMappings = mappings(forwardedClientMappings, "forwarded client");
            trustedProxyPrincipalIds = Set.copyOf(Objects.requireNonNull(trustedProxyPrincipalIds,
                    "trustedProxyPrincipalIds"));
            trustedProxyPrincipalIds.forEach(Permission::requirePrincipal);
            forwardedCertificateFormat = Objects.requireNonNull(forwardedCertificateFormat,
                    "forwardedCertificateFormat");
            forwardedCertificateHeaderName = header(forwardedCertificateHeaderName,
                    "forwardedCertificateHeaderName");
            forwardedCertificateChainHeaderName = header(forwardedCertificateChainHeaderName,
                    "forwardedCertificateChainHeaderName");
            administrativeClientTrust = Objects.requireNonNull(administrativeClientTrust,
                    "administrativeClientTrust");
            if (mode == AdministrativeAuthenticationMode.DIRECT_MTLS) {
                requireDirect(directClientMappings, proxyTransportMappings, forwardedClientMappings,
                        trustedProxyPrincipalIds, forwardedCertificateFormat, forwardedCertificateHeaderName,
                        forwardedCertificateChainHeaderName, administrativeClientTrust,
                        maximumForwardedCertificateBytes, maximumForwardedChainBytes);
            } else {
                requireProxy(directClientMappings, proxyTransportMappings, forwardedClientMappings,
                        trustedProxyPrincipalIds, forwardedCertificateFormat, forwardedCertificateHeaderName,
                        forwardedCertificateChainHeaderName, administrativeClientTrust,
                        maximumForwardedCertificateBytes, maximumForwardedChainBytes);
            }
        }

        private static List<ClientCertificateMapping> mappings(List<ClientCertificateMapping> source,
                String name) {
            List<ClientCertificateMapping> result = List.copyOf(Objects.requireNonNull(source, name));
            if (result.size() > 10_000) throw new IllegalArgumentException("Too many " + name + " mappings");
            if (result.stream().map(ClientCertificateMapping::mappingId).distinct().count() != result.size()) {
                throw new IllegalArgumentException("Duplicate " + name + " mapping identity");
            }
            return result;
        }

        private static Optional<String> header(Optional<String> source, String name) {
            return Objects.requireNonNull(source, name).map(value -> {
                if (!value.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")) {
                    throw new IllegalArgumentException("Forwarded certificate header name is invalid");
                }
                String lower = value.toLowerCase(java.util.Locale.ROOT);
                if (Set.of("authorization", "connection", "content-length", "host", "transfer-encoding",
                        "x-forwarded-for", "forwarded", "x-real-ip").contains(lower)) {
                    throw new IllegalArgumentException("Forwarded certificate header name is prohibited");
                }
                return value;
            });
        }

        private static void requireDirect(List<ClientCertificateMapping> direct,
                List<ClientCertificateMapping> proxy, List<ClientCertificateMapping> forwarded,
                Set<String> trusted, Optional<ForwardedCertificateFormat> format, Optional<String> header,
                Optional<String> chainHeader, Optional<ProviderConfig> trust, int maximumCertificate,
                int maximumChain) {
            if (direct.isEmpty() || !proxy.isEmpty() || !forwarded.isEmpty() || !trusted.isEmpty()
                    || format.isPresent() || header.isPresent() || chainHeader.isPresent() || trust.isPresent()
                    || maximumCertificate != 0 || maximumChain != 0) {
                throw new IllegalArgumentException("Direct authentication configuration is contradictory");
            }
        }

        private static void requireProxy(List<ClientCertificateMapping> direct,
                List<ClientCertificateMapping> proxy, List<ClientCertificateMapping> forwarded,
                Set<String> trusted, Optional<ForwardedCertificateFormat> format, Optional<String> header,
                Optional<String> chainHeader, Optional<ProviderConfig> trust, int maximumCertificate,
                int maximumChain) {
            if (!direct.isEmpty() || proxy.isEmpty() || forwarded.isEmpty() || trusted.isEmpty()
                    || format.isEmpty() || header.isEmpty() || trust.isEmpty()) {
                throw new IllegalArgumentException("Trusted-proxy authentication configuration is incomplete");
            }
            if (maximumCertificate < 512 || maximumCertificate > 1_048_576
                    || maximumChain < 512 || maximumChain > 4_194_304) {
                throw new IllegalArgumentException("Forwarded certificate bound is invalid");
            }
            if (proxy.stream().anyMatch(mapping -> !trusted.contains(mapping.principalId()))) {
                throw new IllegalArgumentException("Proxy mapping is outside the trusted principal set");
            }
            if (proxy.stream().anyMatch(mapping -> mapping.certificateSha256().isEmpty()
                    && mapping.subjectPublicKeyInfoSha256().isEmpty())) {
                throw new IllegalArgumentException("Proxy mapping requires certificate or SPKI commitment");
            }
            if (forwarded.stream().anyMatch(mapping -> mapping.certificateSha256().isEmpty()
                    && mapping.subjectPublicKeyInfoSha256().isEmpty())) {
                throw new IllegalArgumentException("Forwarded client mapping requires certificate or SPKI commitment");
            }
            Set<String> proxyPrincipals = proxy.stream().map(ClientCertificateMapping::principalId)
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (!trusted.equals(proxyPrincipals)) {
                throw new IllegalArgumentException("Trusted proxy principals and mappings differ");
            }
            if (forwarded.stream().map(ClientCertificateMapping::principalId).anyMatch(proxyPrincipals::contains)) {
                throw new IllegalArgumentException("Proxy and end-client principal mappings overlap");
            }
            Set<String> mappingIds = new java.util.HashSet<>();
            if (java.util.stream.Stream.concat(proxy.stream(), forwarded.stream())
                    .anyMatch(mapping -> !mappingIds.add(mapping.mappingId()))) {
                throw new IllegalArgumentException("Proxy authentication mapping identity is duplicated");
            }
            Set<String> proxyCertificates = proxy.stream().flatMap(mapping -> mapping.certificateSha256().stream())
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            Set<String> proxyKeys = proxy.stream().flatMap(mapping -> mapping.subjectPublicKeyInfoSha256().stream())
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (forwarded.stream().anyMatch(mapping -> mapping.certificateSha256()
                    .filter(proxyCertificates::contains).isPresent()
                    || mapping.subjectPublicKeyInfoSha256().filter(proxyKeys::contains).isPresent())) {
                throw new IllegalArgumentException("Proxy and end-client mapping commitments overlap");
            }
            if (format.orElseThrow() == ForwardedCertificateFormat.RFC9440) {
                if (!"Client-Cert".equalsIgnoreCase(header.orElseThrow())
                        || chainHeader.isEmpty()
                        || !"Client-Cert-Chain".equalsIgnoreCase(chainHeader.orElseThrow())) {
                    throw new IllegalArgumentException("RFC 9440 header names are fixed");
                }
            } else if (chainHeader.isPresent()
                    || "Client-Cert".equalsIgnoreCase(header.orElseThrow())
                    || "Client-Cert-Chain".equalsIgnoreCase(header.orElseThrow())) {
                throw new IllegalArgumentException("NGINX compatibility header configuration is invalid");
            }
        }
    }

    /**
     * One exact client-certificate mapping. All present commitments must match.
     *
     * @param mappingId stable mapping identity
     * @param principalId persisted server principal identity
     * @param certificateSha256 optional canonical certificate commitment
     * @param subjectPublicKeyInfoSha256 optional canonical SPKI commitment
     * @param issuerSerialSha256 optional issuer-DER and positive-serial commitment
     */
    public record ClientCertificateMapping(String mappingId, String principalId,
            Optional<String> certificateSha256, Optional<String> subjectPublicKeyInfoSha256,
            Optional<String> issuerSerialSha256) {
        /** Validates stable identities and fixed-size lowercase commitments. */
        public ClientCertificateMapping {
            Permission.requireId(mappingId, "mapping");
            Permission.requirePrincipal(principalId);
            certificateSha256 = digest(certificateSha256, "certificateSha256");
            subjectPublicKeyInfoSha256 = digest(subjectPublicKeyInfoSha256, "subjectPublicKeyInfoSha256");
            issuerSerialSha256 = digest(issuerSerialSha256, "issuerSerialSha256");
            if (certificateSha256.isEmpty() && subjectPublicKeyInfoSha256.isEmpty()
                    && issuerSerialSha256.isEmpty()) {
                throw new IllegalArgumentException("Certificate mapping requires a cryptographic commitment");
            }
        }

        private static Optional<String> digest(Optional<String> source, String name) {
            return Objects.requireNonNull(source, name).map(value -> {
                if (!value.matches("[0-9a-f]{64}")) throw new IllegalArgumentException(name + " is invalid");
                return value;
            });
        }
    }

    /**
     * Bounded worker, queue, admission, deadline and shutdown policy.
     *
     * @param transportWorkers fixed HTTPS handler worker count
     * @param transportQueueCapacity bounded handler backlog
     * @param operationWorkers maximum concurrently executing gateway calls
     * @param operationQueueCapacity bounded waiting gateway calls
     * @param maximumAdmittedRequests maximum requests admitted across parsing and execution
     * @param defaultDeadline default request deadline
     * @param maximumDeadline hard caller deadline ceiling
     * @param gracefulShutdown graceful drain duration
     * @param forcedShutdown forced cancellation and termination duration
     */
    public record Execution(int transportWorkers, int transportQueueCapacity, int operationWorkers,
            int operationQueueCapacity, int maximumAdmittedRequests, Duration defaultDeadline,
            Duration maximumDeadline, Duration gracefulShutdown, Duration forcedShutdown) {
        /** Validates finite positive bounds and duration ordering. */
        public Execution {
            bounded(transportWorkers, 1, 256, "transport worker count");
            bounded(transportQueueCapacity, 1, 65_536, "transport queue capacity");
            bounded(operationWorkers, 1, 256, "operation worker count");
            bounded(operationQueueCapacity, 1, 65_536, "operation queue capacity");
            bounded(maximumAdmittedRequests, 1, 131_072, "admitted request count");
            positive(defaultDeadline, Duration.ofHours(1), "default deadline");
            positive(maximumDeadline, Duration.ofHours(1), "maximum deadline");
            positive(gracefulShutdown, Duration.ofMinutes(5), "graceful shutdown");
            positive(forcedShutdown, Duration.ofMinutes(5), "forced shutdown");
            if (defaultDeadline.compareTo(maximumDeadline) > 0) {
                throw new IllegalArgumentException("Default deadline exceeds the maximum");
            }
        }
    }

    /**
     * Process-local capability references.
     *
     * @param keyUnlockEnvironmentVariable optional external unlock reference
     */
    public record RuntimeCapabilities(Optional<String> keyUnlockEnvironmentVariable) {
        /** Validates the external reference without resolving its secret value. */
        public RuntimeCapabilities {
            keyUnlockEnvironmentVariable = Objects.requireNonNull(keyUnlockEnvironmentVariable,
                    "keyUnlockEnvironmentVariable").map(value -> {
                        if (!value.matches("[A-Z][A-Z0-9_]{0,127}")) {
                            throw new IllegalArgumentException("Key-unlock environment reference is invalid");
                        }
                        return value;
                    });
        }
    }

    private static void bounded(int value, int minimum, int maximum, String name) {
        if (value < minimum || value > maximum) throw new IllegalArgumentException(name + " is invalid");
    }

    private static void positive(Duration value, Duration maximum, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative() || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }
}
