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
package zeroecho.pki.server;

import zeroecho.pki.api.confirmation.CredentialConfirmationInitialization;
import zeroecho.pki.api.confirmation.CredentialConfirmationReview;
import zeroecho.pki.server.acme.AcmeWireBounds;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.confirmation.KeyPossessionProofResponse;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Immutable configuration values for one administrative HTTPS server and its optional listeners.
 *
 * <p>Construction checks local schemas, required values, mode separation and
 * configured bind conflicts. It opens no socket/provider/store and does not
 * authenticate a certificate, read an environment secret or validate live TLS
 * material. Startup resolves provider capabilities and creates the owning realm
 * context; a constructed record alone is not evidence of successful startup.</p>
 *
 * <p>Runtime capabilities use external secret references, not resolved secret
 * values. Provider property maps and other caller-supplied strings are retained
 * as supplied and must not be assumed secret-free or redacted by generated record
 * diagnostics. Avoid rendering/logging complete configuration values.</p>
 *
 * @param version server schema version
 * @param serverName safe bounded operational name
 * @param realm exact realm configuration
 * @param listener HTTPS listener policy
 * @param authentication strict client-certificate mappings
 * @param execution bounded execution and shutdown policy
 * @param runtime process-local capability references
 * @param publicListener optional separately bounded public repository listener
 * @param acmeListener optional separately bounded ACME protocol listener
 * @param estListener optional separately bounded EST protocol listener
 * @param scepListener optional separately bounded SCEP protocol listener
 * @param cmpListener optional separately bounded CMP protocol listener
 * @param auditProjection bounded audit-projection scheduling policy
 */
public record PkiServerConfiguration(int version, String serverName, ServerRealmConfiguration realm,
        Listener listener, Authentication authentication, Execution execution, RuntimeCapabilities runtime,
        Optional<PublicListener> publicListener, Optional<AcmeListener> acmeListener,
        Optional<EstListener> estListener, Optional<ScepListener> scepListener,
        Optional<CmpListener> cmpListener, AuditProjection auditProjection) {
    private static final String EXECUTION = "execution";
    private static final String HYBRID_SDK = "hybridSdk";
    private static final String ADDRESS = "address";
    private static final String TLS_PROVIDER = "tlsProvider";
    private static final int MAX_CERTIFICATE_MAPPINGS = 10_000;

    /**
     * Current server configuration schema.
     */
    public static final int CURRENT_VERSION = 8;

    /**
     * Checks schema, required configuration and listener bind separation without allocating runtime resources.
     *
     * @param version server schema version
     * @param serverName safe bounded operational name
     * @param realm exact realm configuration
     * @param listener HTTPS listener policy
     * @param authentication strict client-certificate mappings
     * @param execution bounded execution and shutdown policy
     * @param runtime process-local capability references
     * @param publicListener optional separately bounded public repository listener
     * @param acmeListener optional separately bounded ACME protocol listener
     * @param estListener optional separately bounded EST protocol listener
     * @param scepListener optional separately bounded SCEP protocol listener
     * @param cmpListener optional separately bounded CMP protocol listener
     * @param auditProjection bounded audit-projection scheduling policy
     * @throws NullPointerException if a required realm/listener/authentication/execution/runtime/audit value or
     *     optional listener container is null
     * @throws IllegalArgumentException if the schema/name, administrative client-certificate requirement or
     *     configured nonzero overlapping bind addresses/ports are invalid
     */
    public PkiServerConfiguration {
        if (version != CURRENT_VERSION) {
            throw new IllegalArgumentException("Unsupported server schema version");
        }
        Permission.requireBounded(serverName, 128, "server name");
        Objects.requireNonNull(realm, "realm");
        Objects.requireNonNull(listener, "listener");
        Objects.requireNonNull(authentication, "authentication");
        Objects.requireNonNull(execution, EXECUTION);
        Objects.requireNonNull(runtime, "runtime");
        publicListener = Objects.requireNonNull(publicListener, "publicListener");
        acmeListener = Objects.requireNonNull(acmeListener, "acmeListener");
        estListener = Objects.requireNonNull(estListener, "estListener");
        scepListener = Objects.requireNonNull(scepListener, "scepListener");
        cmpListener = Objects.requireNonNull(cmpListener, "cmpListener");
        Objects.requireNonNull(auditProjection, "auditProjection");
        if (!listener.clientCertificateRequired()) {
            throw new IllegalArgumentException("Administrative HTTPS requires client certificates");
        }
        publicListener.ifPresent(
                publicConfiguration -> {
                    if (listener.port() != 0 && listener.port() == publicConfiguration.port()) {
                        boolean addressOverlap =
                                listener.address().equals(publicConfiguration.address())
                                        || listener.address().isAnyLocalAddress()
                                        || publicConfiguration.address().isAnyLocalAddress();
                        if (addressOverlap) {
                            throw new IllegalArgumentException(
                                    "Administrative and public listeners conflict");
                        }
                    }
                });
        Optional<PublicListener> exactPublicListener = publicListener;
        Optional<AcmeListener> exactAcmeListener = acmeListener;
        acmeListener.ifPresent(acme -> {
            requireDistinct(listener.address(), listener.port(), acme.address(), acme.port(),
                    "Administrative and ACME listeners conflict");
            exactPublicListener.ifPresent(publicConfiguration -> requireDistinct(publicConfiguration.address(),
                    publicConfiguration.port(), acme.address(), acme.port(),
                    "Public and ACME listeners conflict"));
        });
        estListener.ifPresent(est -> {
            requireDistinct(listener.address(), listener.port(), est.address(), est.port(),
                    "Administrative and EST listeners conflict");
            exactPublicListener.ifPresent(pub -> requireDistinct(pub.address(), pub.port(),
                    est.address(), est.port(), "Public and EST listeners conflict"));
            exactAcmeListener.ifPresent(acme -> requireDistinct(acme.address(), acme.port(),
                    est.address(), est.port(), "ACME and EST listeners conflict"));
        });
        Optional<EstListener> exactEstListener = estListener;
        scepListener.ifPresent(scep -> {
            requireDistinct(listener.address(), listener.port(), scep.address(), scep.port(),
                    "Administrative and SCEP listeners conflict");
            exactPublicListener.ifPresent(pub -> requireDistinct(pub.address(), pub.port(),
                    scep.address(), scep.port(), "Public and SCEP listeners conflict"));
            exactAcmeListener.ifPresent(acme -> requireDistinct(acme.address(), acme.port(),
                    scep.address(), scep.port(), "ACME and SCEP listeners conflict"));
            exactEstListener.ifPresent(est -> requireDistinct(est.address(), est.port(),
                    scep.address(), scep.port(), "EST and SCEP listeners conflict"));
        });
        Optional<ScepListener> exactScepListener = scepListener;
        cmpListener.ifPresent(cmp -> {
            requireDistinct(listener.address(), listener.port(), cmp.address(), cmp.port(),
                    "Administrative and CMP listeners conflict");
            exactPublicListener.ifPresent(pub -> requireDistinct(pub.address(), pub.port(),
                    cmp.address(), cmp.port(), "Public and CMP listeners conflict"));
            exactAcmeListener.ifPresent(acme -> requireDistinct(acme.address(), acme.port(),
                    cmp.address(), cmp.port(), "ACME and CMP listeners conflict"));
            exactEstListener.ifPresent(est -> requireDistinct(est.address(), est.port(),
                    cmp.address(), cmp.port(), "EST and CMP listeners conflict"));
            exactScepListener.ifPresent(scep -> requireDistinct(scep.address(), scep.port(),
                    cmp.address(), cmp.port(), "SCEP and CMP listeners conflict"));
        });
    }

    /**
     * Creates a configuration with ACME disabled.
     *
     * <p>ACME, EST, SCEP and CMP listeners are absent; audit projection uses its defaults.</p>
     *
     * @param version configuration schema version
     * @param serverName nonblank server name
     * @param realm realm configuration
     * @param listener administrative HTTPS listener
     * @param authentication administrative authentication policy
     * @param execution bounded request-execution policy
     * @param runtime explicit process-local runtime capabilities
     * @param publicListener optional public repository listener
     * @throws NullPointerException if a required supplied configuration reference or container is null
     * @throws IllegalArgumentException if delegated local configuration constraints fail
     */
    public PkiServerConfiguration(int version, String serverName, ServerRealmConfiguration realm,
            Listener listener, Authentication authentication, Execution execution, RuntimeCapabilities runtime,
            Optional<PublicListener> publicListener) {
        this(version, serverName, realm, listener, authentication, execution, runtime, publicListener,
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), AuditProjection.defaults());
    }

    /**
     * Creates a configuration with default audit projection.
     *
     * <p>EST, SCEP and CMP listeners are absent; audit projection uses its defaults.</p>
     *
     * @param version configuration schema version
     * @param serverName nonblank server name
     * @param realm realm configuration
     * @param listener administrative HTTPS listener
     * @param authentication administrative authentication policy
     * @param execution bounded request-execution policy
     * @param runtime explicit process-local runtime capabilities
     * @param publicListener optional public repository listener
     * @param acmeListener optional ACME protocol listener
     * @throws NullPointerException if a required supplied configuration reference or container is null
     * @throws IllegalArgumentException if delegated local configuration constraints fail
     */
    public PkiServerConfiguration(int version, String serverName, ServerRealmConfiguration realm,
            Listener listener, Authentication authentication, Execution execution, RuntimeCapabilities runtime,
            Optional<PublicListener> publicListener, Optional<AcmeListener> acmeListener) {
        this(version, serverName, realm, listener, authentication, execution, runtime, publicListener, acmeListener,
                Optional.empty(), Optional.empty(), Optional.empty(), AuditProjection.defaults());
    }

    /**
     * Creates a configuration with the public repository and ACME listeners disabled.
     *
     * <p>All optional listeners are absent; audit projection uses its defaults.</p>
     *
     * @param version configuration schema version
     * @param serverName nonblank server name
     * @param realm realm configuration
     * @param listener administrative HTTPS listener
     * @param authentication administrative authentication policy
     * @param execution bounded request-execution policy
     * @param runtime explicit process-local runtime capabilities
     * @throws NullPointerException if a required supplied configuration reference or container is null
     * @throws IllegalArgumentException if delegated local configuration constraints fail
     */
    public PkiServerConfiguration(int version, String serverName, ServerRealmConfiguration realm,
            Listener listener, Authentication authentication, Execution execution, RuntimeCapabilities runtime) {
        this(version, serverName, realm, listener, authentication, execution, runtime, Optional.empty(),
                Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), AuditProjection.defaults());
    }

    /**
     * Bounded audit-projection policy, independently applied to revocation and each evidence family.
     *
     * @param maximumRecords maximum records examined per projection pass, from 1 through 4096
     * @param maximumSinkCalls maximum sink calls per projection pass, from 1 through the record bound
     * @param idleInterval positive polling delay, at most five minutes
     */
    public record AuditProjection(int maximumRecords, int maximumSinkCalls, Duration idleInterval) {
        /**
         * Checks the per-pass record/sink limits and positive idle interval.
         *
         * @param maximumRecords maximum records examined per projection pass, from 1 through 4096
         * @param maximumSinkCalls maximum sink calls per projection pass, from 1 through the record bound
         * @param idleInterval positive polling delay, at most five minutes
         * @throws NullPointerException if idleInterval is null
         * @throws IllegalArgumentException if record/sink limits or the positive at-most-five-minute idle
         *     interval are invalid
         */
        public AuditProjection {
            bounded(maximumRecords, 1, 4096, "audit projection record count");
            bounded(maximumSinkCalls, 1, maximumRecords, "audit projection sink call count");
            positive(idleInterval, Duration.ofMinutes(5), "audit projection idle interval");
        }

        /**
         * Returns the current production defaults.
         *
         * @return 256 records, 64 sink calls, and a two-second idle interval
         */
        public static AuditProjection defaults() {
            return new AuditProjection(256, 64, Duration.ofSeconds(2));
        }
    }

    /**
     * Administrative HTTPS listener configuration.
     *
     * <p>The listener value retains its supplied immutable provider reference.
     * Client-certificate-required is enforced by the enclosing server configuration,
     * not this nested constructor. SDK routes remain disabled when hybridSdk is
     * empty; adding the option does not create or authenticate a listener.</p>
     *
     * @param address parsed canonical literal bind address
     * @param port TCP port, where zero requests an ephemeral test port
     * @param tlsProvider explicitly selected TLS material provider
     * @param clientCertificateRequired must be {@code true}
     * @param maximumHeaderBytes bounded aggregate decoded header bytes
     * @param maximumBodyBytes bounded request body bytes
     * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
     */
    public record Listener(InetAddress address, int port, ProviderConfig tlsProvider,
            boolean clientCertificateRequired, int maximumHeaderBytes, int maximumBodyBytes, Optional<HybridSdkListener> hybridSdk) {
        /** Exact canonical unpadded Base64url character bound for one proof response. */
        // Existing public constant name is part of the configuration API.
        @SuppressWarnings("PMD.LongVariable")
        public static final int MAXIMUM_PROOF_RESPONSE_BASE64URL_CHARACTERS =
                KeyPossessionProofResponse.MAXIMUM_BYTES / 3 * 4
                        + (KeyPossessionProofResponse.MAXIMUM_BYTES % 3 == 0
                                ? 0
                                : KeyPossessionProofResponse.MAXIMUM_BYTES % 3 + 1);

        private static final int MAX_JSON_ESCAPE_BYTES = 6;
        private static final int SHA_256_HEX_CHARACTERS = 64;
        private static final String COMPLETION_REQUEST_FRAMING =
                "{\"version\":1,\"authorityId\":\"\",\"arguments\":{"
                + "\"credentialId\":\"\",\"expectedLifecycleRevision\":1,"
                + "\"expectedLifecycleRecordCommitment\":\"\","
                + "\"expectedChallengeRecordCommitment\":\"\",\"response\":\"\"}}";

        /**
         * Minimum administrative body bound that can carry the canonical maximum proof-completion
         * request, including worst-case JSON escaping of both IDs.
         */
        public static final int MINIMUM_BODY_BYTES =
                COMPLETION_REQUEST_FRAMING.length()
                        + MAX_JSON_ESCAPE_BYTES
                                * (CredentialConfirmationReview.MAXIMUM_AUTHORITY_ID_UTF8_BYTES
                                        + CredentialConfirmationInitialization
                                                .MAXIMUM_CREDENTIAL_ID_UTF8_BYTES)
                        + 2 * SHA_256_HEX_CHARACTERS
                        + MAXIMUM_PROOF_RESPONSE_BASE64URL_CHARACTERS;

        /**
         * Preserves the SDK-disabled listener constructor.
         *
         * @param address parsed canonical literal bind address
         * @param port TCP port, where zero requests an ephemeral test port
         * @param tlsProvider explicitly selected TLS material provider
         * @param clientCertificateRequired must be {@code true}
         * @param maximumHeaderBytes bounded aggregate decoded header bytes
         * @param maximumBodyBytes bounded request body bytes
         * @throws NullPointerException if a required supplied configuration reference or container
         *     is null
         * @throws IllegalArgumentException if delegated local configuration constraints fail
         */
        public Listener(
                InetAddress address,
                int port,
                ProviderConfig tlsProvider,
                boolean clientCertificateRequired,
                int maximumHeaderBytes,
                int maximumBodyBytes) {
            this(
                    address,
                    port,
                    tlsProvider,
                    clientCertificateRequired,
                    maximumHeaderBytes,
                    maximumBodyBytes,
                    Optional.empty());
        }

        /**
         * Checks required address/TLS configuration, body/header bounds and optional SDK envelope capacity.
         *
         * @param address parsed canonical literal bind address
         * @param port TCP port, where zero requests an ephemeral test port
         * @param tlsProvider explicitly selected TLS material provider
         * @param clientCertificateRequired must be {@code true}
         * @param maximumHeaderBytes bounded aggregate decoded header bytes
         * @param maximumBodyBytes bounded request body bytes
         * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
         * @throws NullPointerException if address, tlsProvider or the SDK option container is null
         * @throws IllegalArgumentException if port, 1024-through-1048576 header budget,
         *     MINIMUM_BODY_BYTES-through-16777216 body budget or SDK budget is invalid
         */
        public Listener {
            Objects.requireNonNull(hybridSdk, HYBRID_SDK);
            hybridSdk.ifPresent(value -> value.requireBodyBudget(maximumBodyBytes));
            Objects.requireNonNull(address, ADDRESS);
            if (port < 0 || port > 65_535) {
                throw new IllegalArgumentException("Listener port is invalid");
            }
            Objects.requireNonNull(tlsProvider, TLS_PROVIDER);
            if (maximumHeaderBytes < 1_024 || maximumHeaderBytes > 1_048_576) {
                throw new IllegalArgumentException("Header bound is invalid");
            }
            if (maximumBodyBytes < MINIMUM_BODY_BYTES || maximumBodyBytes > 16_777_216) {
                throw new IllegalArgumentException("Body bound is invalid");
            }
        }

        /**
         * Returns the listener socket address without DNS resolution.
         *
         * @return exact socket address
         */
        public InetSocketAddress socketAddress() {
            return new InetSocketAddress(address, port);
        }
    }

    /**
     * Mode-separated administrative client-certificate mapping policy.
     *
     * <p>Lists/sets are copied into unmodifiable containers retaining immutable mapping elements.
     * Structural checks do not establish live certificate trust, principal enablement or
     * trusted-proxy authorization. Direct mode requires nonempty direct mappings and no forwarding
     * fields; proxy mode independently configures proxy and forwarded-client mappings/trust, with
     * explicit exclusions.
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
    // Existing component names define public record accessors.
    @SuppressWarnings("PMD.LongVariable")
    public record Authentication(
            AdministrativeAuthenticationMode mode,
            List<ClientCertificateMapping> directClientMappings,
            List<ClientCertificateMapping> proxyTransportMappings,
            List<ClientCertificateMapping> forwardedClientMappings,
            Set<String> trustedProxyPrincipalIds,
            Optional<ForwardedCertificateFormat> forwardedCertificateFormat,
            Optional<String> forwardedCertificateHeaderName,
            Optional<String> forwardedCertificateChainHeaderName,
            Optional<ProviderConfig> administrativeClientTrust,
            int maximumForwardedCertificateBytes,
            int maximumForwardedChainBytes) {
        /**
         * Snapshots mapping lists and trusted principals and checks direct/proxy mode separation and header
         * policy.
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
         * @throws NullPointerException if mode, a mapping list/element, trusted-principal set/element or an
         *     optional container is null
         * @throws IllegalArgumentException if mapping counts/IDs, principal/header grammar, mode fields, trust
         *     policy or proxy/end-client exclusion constraints are invalid
         */
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
            ProxyInputs inputs =
                    new ProxyInputs(
                            directClientMappings,
                            proxyTransportMappings,
                            forwardedClientMappings,
                            trustedProxyPrincipalIds,
                            forwardedCertificateFormat,
                            forwardedCertificateHeaderName,
                            forwardedCertificateChainHeaderName,
                            administrativeClientTrust,
                            maximumForwardedCertificateBytes,
                            maximumForwardedChainBytes);
            if (mode == AdministrativeAuthenticationMode.DIRECT_MTLS) {
                requireDirect(inputs);
            } else {
                requireProxy(inputs);
            }
        }

        private static List<ClientCertificateMapping> mappings(List<ClientCertificateMapping> source,
                String name) {
            List<ClientCertificateMapping> result = List.copyOf(Objects.requireNonNull(source, name));
            if (result.size() > MAX_CERTIFICATE_MAPPINGS) {
                throw new IllegalArgumentException("Too many " + name + " mappings");
            }
            if (result.stream().map(ClientCertificateMapping::mappingId).distinct().count() != result.size()) {
                throw new IllegalArgumentException("Duplicate " + name + " mapping identity");
            }
            return result;
        }

        private static Optional<String> header(Optional<String> source, String name) {
            return Objects.requireNonNull(source, name)
                    .map(
                            value -> {
                                if (!value.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")) {
                                    throw new IllegalArgumentException(
                                            "Forwarded certificate header name is invalid");
                                }
                                String lower = value.toLowerCase(java.util.Locale.ROOT);
                                if (Set.of(
                                                "authorization",
                                                "connection",
                                                "content-length",
                                                "host",
                                                "transfer-encoding",
                                                "x-forwarded-for",
                                                "forwarded",
                                                "x-real-ip")
                                        .contains(lower)) {
                                    throw new IllegalArgumentException(
                                            "Forwarded certificate header name is prohibited");
                                }
                                return value;
                            });
        }

        private static void requireDirect(ProxyInputs input) {
            if (input.direct().isEmpty()
                    || !input.proxy().isEmpty()
                    || !input.forwarded().isEmpty()
                    || !input.trusted().isEmpty()
                    || input.format().isPresent()
                    || input.header().isPresent()
                    || input.chainHeader().isPresent()
                    || input.trust().isPresent()
                    || input.maximumCertificate() != 0
                    || input.maximumChain() != 0) {
                throw new IllegalArgumentException(
                        "Direct authentication configuration is contradictory");
            }
        }

        private static void requireProxy(ProxyInputs input) {
            requireProxyBounds(input);
            requireProxyCommitments(input);
            Set<String> proxyPrincipals =
                    input.proxy().stream()
                            .map(ClientCertificateMapping::principalId)
                            .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (!input.trusted().equals(proxyPrincipals)) {
                throw new IllegalArgumentException("Trusted proxy principals and mappings differ");
            }
            if (input.forwarded().stream()
                    .map(ClientCertificateMapping::principalId)
                    .anyMatch(proxyPrincipals::contains)) {
                throw new IllegalArgumentException(
                        "Proxy and end-client principal mappings overlap");
            }
            Set<String> mappingIds = new java.util.HashSet<>();
            if (java.util.stream.Stream.concat(input.proxy().stream(), input.forwarded().stream())
                    .anyMatch(mapping -> !mappingIds.add(mapping.mappingId()))) {
                throw new IllegalArgumentException(
                        "Proxy authentication mapping identity is duplicated");
            }
            Set<String> proxyCertificates =
                    input.proxy().stream()
                            .flatMap(mapping -> mapping.certificateSha256().stream())
                            .collect(java.util.stream.Collectors.toUnmodifiableSet());
            Set<String> proxyKeys =
                    input.proxy().stream()
                            .flatMap(mapping -> mapping.subjectPublicKeyInfoSha256().stream())
                            .collect(java.util.stream.Collectors.toUnmodifiableSet());
            if (input.forwarded().stream()
                    .anyMatch(
                            mapping ->
                                    mapping.certificateSha256()
                                                    .filter(proxyCertificates::contains)
                                                    .isPresent()
                                            || mapping.subjectPublicKeyInfoSha256()
                                                    .filter(proxyKeys::contains)
                                                    .isPresent())) {
                throw new IllegalArgumentException(
                        "Proxy and end-client mapping commitments overlap");
            }
            requireForwardingHeaders(input);
        }

        private static void requireProxyBounds(ProxyInputs input) {
            if (!input.direct().isEmpty()
                    || input.proxy().isEmpty()
                    || input.forwarded().isEmpty()
                    || input.trusted().isEmpty()
                    || input.format().isEmpty()
                    || input.header().isEmpty()
                    || input.trust().isEmpty()) {
                throw new IllegalArgumentException(
                        "Trusted-proxy authentication configuration is incomplete");
            }
            if (input.maximumCertificate() < 512
                    || input.maximumCertificate() > 1_048_576
                    || input.maximumChain() < 512
                    || input.maximumChain() > 4_194_304) {
                throw new IllegalArgumentException("Forwarded certificate bound is invalid");
            }
        }

        private static void requireProxyCommitments(ProxyInputs input) {
            if (input.proxy().stream()
                    .anyMatch(mapping -> !input.trusted().contains(mapping.principalId()))) {
                throw new IllegalArgumentException(
                        "Proxy mapping is outside the trusted principal set");
            }
            if (input.proxy().stream()
                    .anyMatch(
                            mapping ->
                                    mapping.certificateSha256().isEmpty()
                                            && mapping.subjectPublicKeyInfoSha256().isEmpty())) {
                throw new IllegalArgumentException(
                        "Proxy mapping requires certificate or SPKI commitment");
            }
            if (input.forwarded().stream()
                    .anyMatch(
                            mapping ->
                                    mapping.certificateSha256().isEmpty()
                                            && mapping.subjectPublicKeyInfoSha256().isEmpty())) {
                throw new IllegalArgumentException(
                        "Forwarded client mapping requires certificate or SPKI commitment");
            }
        }

        private static void requireForwardingHeaders(ProxyInputs input) {
            if (input.format().orElseThrow() == ForwardedCertificateFormat.RFC9440) {
                if (!"Client-Cert".equalsIgnoreCase(input.header().orElseThrow())
                        || input.chainHeader().isEmpty()
                        || !"Client-Cert-Chain"
                                .equalsIgnoreCase(input.chainHeader().orElseThrow())) {
                    throw new IllegalArgumentException("RFC 9440 header names are fixed");
                }
            } else if (input.chainHeader().isPresent()
                    || "Client-Cert".equalsIgnoreCase(input.header().orElseThrow())
                    || "Client-Cert-Chain".equalsIgnoreCase(input.header().orElseThrow())) {
                throw new IllegalArgumentException(
                        "NGINX compatibility header configuration is invalid");
            }
        }

        /** Normalized authentication coordinates; construction adds no validation or ownership. */
        private record ProxyInputs(
                List<ClientCertificateMapping> direct,
                List<ClientCertificateMapping> proxy,
                List<ClientCertificateMapping> forwarded,
                Set<String> trusted,
                Optional<ForwardedCertificateFormat> format,
                Optional<String> header,
                Optional<String> chainHeader,
                Optional<ProviderConfig> trust,
                int maximumCertificate,
                int maximumChain) {}
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
        /**
         * Checks identity grammar and present digest spellings without looking up a principal or certificate.
         *
         * @param mappingId stable mapping identity
         * @param principalId persisted server principal identity
         * @param certificateSha256 optional canonical certificate commitment
         * @param subjectPublicKeyInfoSha256 optional canonical SPKI commitment
         * @param issuerSerialSha256 optional issuer-DER and positive-serial commitment
         * @throws NullPointerException if a digest option container is null
         * @throws IllegalArgumentException if identity/digest grammar is invalid or no cryptographic selector
         *     is present
         */
        public ClientCertificateMapping {
            Permission.requireId(mappingId, "mapping");
            Permission.requirePrincipal(principalId);
            certificateSha256 = digest(certificateSha256, "certificateSha256");
            subjectPublicKeyInfoSha256 =
                    digest(subjectPublicKeyInfoSha256, "subjectPublicKeyInfoSha256");
            issuerSerialSha256 = digest(issuerSerialSha256, "issuerSerialSha256");
            if (certificateSha256.isEmpty() && subjectPublicKeyInfoSha256.isEmpty()
                    && issuerSerialSha256.isEmpty()) {
                throw new IllegalArgumentException(
                        "Certificate mapping requires a cryptographic commitment");
            }
        }

        private static Optional<String> digest(Optional<String> source, String name) {
            return Objects.requireNonNull(source, name)
                    .map(
                            value -> {
                                if (!value.matches("[0-9a-f]{64}")) {
                                    throw new IllegalArgumentException(name + " is invalid");
                                }
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
        /**
         * Checks positive finite worker/queue/admission limits and deadline/shutdown duration ordering.
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
         * @throws NullPointerException if a deadline or shutdown duration is null
         * @throws IllegalArgumentException if integer budgets, positive duration ceilings or
         *     default-versus-maximum deadline ordering are invalid
         */
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
     * Separately bounded public repository listener configuration.
     *
     * <p>This listener is distinct from administrative mutual TLS. Explicit SDK
     * OCSP opt-in requires TLS even when loopback plaintext development is otherwise
     * permitted, and remains the separate SDK F4/F5 profile rather than standard
     * AltSignature OCSP. A published console path requires TLS, trusted-proxy mode
     * and exactly /public/v1. No route is published merely by constructing a value.</p>
     *
     * @param address canonical bind address
     * @param port TCP port, including zero for an ephemeral test listener
     * @param tlsProvider optional explicit TLS provider; absent only for explicitly permitted loopback
     *     development
     * @param allowPlaintextLoopback whether the loopback-only development exception is selected
     * @param authentication direct or trusted-proxy optional-client authentication configuration
     * @param maximumHeaderBytes bounded public request-header bytes
     * @param maximumBodyBytes bounded public request-body bytes; repository methods still reject bodies
     * @param execution isolated public transport and stream execution bounds
     * @param maximumStreamDuration finite stream deadline
     * @param publicImmutableCache immutable-object public cache duration
     * @param publicAliasCache stable-alias public cache duration
     * @param authorityListExposed whether safe public authority metadata routes are enabled
     * @param consoleBasePath explicitly provisioned same-origin public route, absent when not published to the
     *     console
     * @param hybridSdk explicit optional SDK OCSP origin; absent preserves native-only behavior
     */
    public record PublicListener(InetAddress address, int port, Optional<ProviderConfig> tlsProvider,
            boolean allowPlaintextLoopback, Authentication authentication, int maximumHeaderBytes,
            int maximumBodyBytes, Execution execution,
            Duration maximumStreamDuration, Duration publicImmutableCache, Duration publicAliasCache,
            boolean authorityListExposed, Optional<String> consoleBasePath, Optional<HybridSdkListener> hybridSdk) {
        /**
         * Creates a listener without asserting a published same-origin console route.
         *
         * @param address bind address
         * @param port bind port, zero requests an ephemeral port
         * @param tlsProvider optional TLS configuration
         * @param allowPlaintextLoopback explicit local plaintext permission
         * @param authentication public authentication policy
         * @param maximumHeaderBytes header bound
         * @param maximumBodyBytes body bound
         * @param execution independent execution limits
         * @param maximumStreamDuration stream deadline
         * @param publicImmutableCache immutable cache lifetime
         * @param publicAliasCache alias cache lifetime
         * @param authorityListExposed safe public authority listing permission
         * @throws NullPointerException if a required supplied configuration reference or container
         *     is null
         * @throws IllegalArgumentException if delegated local configuration constraints fail
         */
        // Preserve the existing source and binary configuration-constructor signature.
        @SuppressWarnings("PMD.ExcessiveParameterList")
        public PublicListener(
                InetAddress address,
                int port,
                Optional<ProviderConfig> tlsProvider,
                boolean allowPlaintextLoopback,
                Authentication authentication,
                int maximumHeaderBytes,
                int maximumBodyBytes,
                Execution execution,
                Duration maximumStreamDuration,
                Duration publicImmutableCache,
                Duration publicAliasCache,
                boolean authorityListExposed) {
            this(address,port,tlsProvider,allowPlaintextLoopback,authentication,maximumHeaderBytes,maximumBodyBytes,
                    execution,maximumStreamDuration,publicImmutableCache,publicAliasCache,authorityListExposed,Optional.empty());
        }

        /**
         * Preserves public listener configuration without SDK opt-in.
         *
         * @param address bind address
         * @param port TCP port
         * @param tlsProvider explicit TLS provider
         * @param allowPlaintextLoopback loopback development exception
         * @param authentication authentication policy
         * @param maximumHeaderBytes header budget
         * @param maximumBodyBytes body budget
         * @param execution execution limits
         * @param maximumStreamDuration finite deadline
         * @param publicImmutableCache immutable cache lifetime
         * @param publicAliasCache alias cache lifetime
         * @param authorityListExposed listing opt-in
         * @param consoleBasePath published console path
         * @throws NullPointerException if a required supplied configuration reference or container
         *     is null
         * @throws IllegalArgumentException if delegated local configuration constraints fail
         */
        // Preserve the existing source and binary configuration-constructor signature.
        @SuppressWarnings("PMD.ExcessiveParameterList")
        public PublicListener(
                InetAddress address,
                int port,
                Optional<ProviderConfig> tlsProvider,
                boolean allowPlaintextLoopback,
                Authentication authentication,
                int maximumHeaderBytes,
                int maximumBodyBytes,
                Execution execution,
                Duration maximumStreamDuration,
                Duration publicImmutableCache,
                Duration publicAliasCache,
                boolean authorityListExposed,
                Optional<String> consoleBasePath) {
            this(address,port,tlsProvider,allowPlaintextLoopback,authentication,maximumHeaderBytes,maximumBodyBytes,
                    execution,maximumStreamDuration,publicImmutableCache,publicAliasCache,authorityListExposed,consoleBasePath,Optional.empty());
        }
        /**
         * Checks independent transport/budget policy without opening a socket or resolving TLS material.
         *
         * @param address canonical bind address
         * @param port TCP port, including zero for an ephemeral test listener
         * @param tlsProvider optional explicit TLS provider; absent only for explicitly permitted loopback
         *     development
         * @param allowPlaintextLoopback whether the loopback-only development exception is selected
         * @param authentication direct or trusted-proxy optional-client authentication configuration
         * @param maximumHeaderBytes bounded public request-header bytes
         * @param maximumBodyBytes bounded public request-body bytes; repository methods still reject bodies
         * @param execution isolated public transport and stream execution bounds
         * @param maximumStreamDuration finite stream deadline
         * @param publicImmutableCache immutable-object public cache duration
         * @param publicAliasCache stable-alias public cache duration
         * @param authorityListExposed whether safe public authority metadata routes are enabled
         * @param consoleBasePath explicitly provisioned same-origin public route, absent when not published to
         *     the console
         * @param hybridSdk explicit optional SDK OCSP origin; absent preserves native-only behavior
         * @throws NullPointerException if a required transport/execution value, duration or optional container
         *     is null
         * @throws IllegalArgumentException if port/budgets/durations, TLS-versus-loopback policy, console route
         *     or SDK transport/budget constraints are invalid
         */
        public PublicListener {
            Objects.requireNonNull(address, ADDRESS);
            hybridSdk = Objects.requireNonNull(hybridSdk, HYBRID_SDK);
            if (hybridSdk.isPresent() && tlsProvider.isEmpty()) {
                throw new IllegalArgumentException("SDK OCSP listener requires TLS");
            }
            hybridSdk.ifPresent(value -> value.requireBodyBudget(maximumBodyBytes));
            if (port < 0 || port > 65_535) {
                throw new IllegalArgumentException("Public listener port is invalid");
            }
            consoleBasePath=Objects.requireNonNull(consoleBasePath,"consoleBasePath");
            if (consoleBasePath.filter(value -> !"/public/v1".equals(value)).isPresent()) {
                throw new IllegalArgumentException("Published public repository path is invalid");
            }
            tlsProvider = Objects.requireNonNull(tlsProvider, TLS_PROVIDER);
            Objects.requireNonNull(authentication, "authentication");
            if(consoleBasePath.isPresent()&&(tlsProvider.isEmpty()||authentication.mode()!=AdministrativeAuthenticationMode.TRUSTED_REVERSE_PROXY)) {
                throw new IllegalArgumentException(
                        "Published public console route requires TLS and trusted reverse proxy"
                            + " authentication");
            }
            bounded(maximumHeaderBytes, 1_024, 1_048_576, "public header bound");
            bounded(maximumBodyBytes, 1, 65_536, "public body bound");
            Objects.requireNonNull(execution, EXECUTION);
            positive(maximumStreamDuration, Duration.ofHours(1), "maximum stream duration");
            nonNegative(publicImmutableCache, Duration.ofDays(365), "immutable cache duration");
            nonNegative(publicAliasCache, Duration.ofDays(1), "alias cache duration");
            if (tlsProvider.isEmpty() && (!allowPlaintextLoopback || !address.isLoopbackAddress())) {
                throw new IllegalArgumentException("Public listener TLS is required");
            }
            if (tlsProvider.isPresent() && allowPlaintextLoopback) {
                throw new IllegalArgumentException(
                        "Public listener transport policy is contradictory");
            }
        }

        /**
         * Returns the public listener socket address without DNS resolution.
         *
         * @return exact public socket address
         */
        public InetSocketAddress socketAddress() {
            return new InetSocketAddress(address, port);
        }
    }

    /**
     * Closed ACME listener transport topologies.
     */
    public enum AcmeTransportMode {
        /**
         * Client connects directly through server-authenticated TLS.
         */
        DIRECT_TLS,
        /**
         * An authenticated trusted proxy terminates the external connection.
         */
        TRUSTED_REVERSE_PROXY
    }

    /**
     * Separately bounded ACME listener and protocol-security configuration.
     *
     * @param listenerId stable process-local listener identity used for nonce binding
     * @param address canonical bind address
     * @param port TCP port, including zero for deterministic tests
     * @param tlsProvider explicit server TLS identity and proxy trust provider
     * @param transportMode direct server-auth TLS or authenticated trusted proxy
     * @param proxyTransportMappings exact proxy certificate commitments
     * @param trustedProxyPrincipalIds explicitly admitted infrastructure principals
     * @param externalBaseUri configured public ACME URL authority for JWS binding
     * @param maximumHeaderBytes bounded request-header bytes
     * @param maximumBodyBytes bounded JWS/CSR request body bytes
     * @param execution isolated protocol workers, queue, admission, and deadlines
     * @param validationExecution isolated challenge-validation workers and queue
     * @param nonceLifetime finite replay-nonce lifetime
     * @param maximumOutstandingNonces bounded process-local nonce population
     * @param maximumAccountsPresented bounded administrative account page size
     * @param maximumOrdersPresented bounded account order page size
     * @param admissionWindow finite in-memory rate window
     * @param maximumNewAccountsPerWindow bounded directory-wide account admission
     * @param maximumNewOrdersPerAccountWindow bounded per-account order admission
     * @param maximumPendingOrdersPerAccount bounded durable pending-order population
     * @param maximumChallengeValidationsPerAccountWindow bounded validation admission
     * @param maximumConcurrentFinalizations bounded listener-wide finalization concurrency
     * @param challengeProviders explicitly enabled provider configurations
     * @param eabProviders explicitly enabled secret-confining EAB provider configurations
     * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
     */
    // Component names are established public accessors.
    @SuppressWarnings("PMD.LongVariable")
    public record AcmeListener(
            String listenerId,
            InetAddress address,
            int port,
            ProviderConfig tlsProvider,
            AcmeTransportMode transportMode,
            List<ClientCertificateMapping> proxyTransportMappings,
            Set<String> trustedProxyPrincipalIds,
            URI externalBaseUri,
            int maximumHeaderBytes,
            int maximumBodyBytes,
            Execution execution,
            Execution validationExecution,
            Duration nonceLifetime,
            int maximumOutstandingNonces,
            int maximumAccountsPresented,
            int maximumOrdersPresented,
            Duration admissionWindow,
            int maximumNewAccountsPerWindow,
            int maximumNewOrdersPerAccountWindow,
            int maximumPendingOrdersPerAccount,
            int maximumChallengeValidationsPerAccountWindow,
            int maximumConcurrentFinalizations,
            List<ProviderConfig> challengeProviders,
            List<ProviderConfig> eabProviders,
            Optional<HybridSdkListener> hybridSdk) {
        /**
         * Preserves the SDK-disabled listener constructor.
         *
         * @param listenerId stable process-local listener identity used for nonce binding
         * @param address canonical bind address
         * @param port TCP port, including zero for deterministic tests
         * @param tlsProvider explicit server TLS identity and proxy trust provider
         * @param transportMode direct server-auth TLS or authenticated trusted proxy
         * @param proxyTransportMappings exact proxy certificate commitments
         * @param trustedProxyPrincipalIds explicitly admitted infrastructure principals
         * @param externalBaseUri configured public ACME URL authority for JWS binding
         * @param maximumHeaderBytes bounded request-header bytes
         * @param maximumBodyBytes bounded JWS/CSR request body bytes
         * @param execution isolated protocol workers, queue, admission, and deadlines
         * @param validationExecution isolated challenge-validation workers and queue
         * @param nonceLifetime finite replay-nonce lifetime
         * @param maximumOutstandingNonces bounded process-local nonce population
         * @param maximumAccountsPresented bounded administrative account page size
         * @param maximumOrdersPresented bounded account order page size
         * @param admissionWindow finite in-memory rate window
         * @param maximumNewAccountsPerWindow bounded directory-wide account admission
         * @param maximumNewOrdersPerAccountWindow bounded per-account order admission
         * @param maximumPendingOrdersPerAccount bounded durable pending-order population
         * @param maximumChallengeValidationsPerAccountWindow bounded validation admission
         * @param maximumConcurrentFinalizations bounded listener-wide finalization concurrency
         * @param challengeProviders explicitly enabled provider configurations
         * @param eabProviders explicitly enabled secret-confining EAB provider configurations
         * @throws NullPointerException if a required supplied configuration reference or container
         *     is null
         * @throws IllegalArgumentException if delegated local configuration constraints fail
         */
        // Preserve the existing source and binary configuration-constructor signature.
        @SuppressWarnings("PMD.ExcessiveParameterList")
        public AcmeListener(
                String listenerId,
                InetAddress address,
                int port,
                ProviderConfig tlsProvider,
                AcmeTransportMode transportMode,
                List<ClientCertificateMapping> proxyTransportMappings,
                Set<String> trustedProxyPrincipalIds,
                URI externalBaseUri,
                int maximumHeaderBytes,
                int maximumBodyBytes,
                Execution execution,
                Execution validationExecution,
                Duration nonceLifetime,
                int maximumOutstandingNonces,
                int maximumAccountsPresented,
                int maximumOrdersPresented,
                Duration admissionWindow,
                int maximumNewAccountsPerWindow,
                int maximumNewOrdersPerAccountWindow,
                int maximumPendingOrdersPerAccount,
                int maximumChallengeValidationsPerAccountWindow,
                int maximumConcurrentFinalizations,
                List<ProviderConfig> challengeProviders,
                List<ProviderConfig> eabProviders) {
            this(listenerId, address, port, tlsProvider, transportMode, proxyTransportMappings, trustedProxyPrincipalIds, externalBaseUri, maximumHeaderBytes, maximumBodyBytes, execution, validationExecution, nonceLifetime, maximumOutstandingNonces, maximumAccountsPresented, maximumOrdersPresented, admissionWindow, maximumNewAccountsPerWindow, maximumNewOrdersPerAccountWindow, maximumPendingOrdersPerAccount, maximumChallengeValidationsPerAccountWindow, maximumConcurrentFinalizations, challengeProviders, eabProviders, Optional.empty());
        }

        /**
         * Snapshots proxy/provider collections and checks explicit ACME origin/topology and finite protocol
         * budgets.
         *
         * @param listenerId stable process-local listener identity used for nonce binding
         * @param address canonical bind address
         * @param port TCP port, including zero for deterministic tests
         * @param tlsProvider explicit server TLS identity and proxy trust provider
         * @param transportMode direct server-auth TLS or authenticated trusted proxy
         * @param proxyTransportMappings exact proxy certificate commitments
         * @param trustedProxyPrincipalIds explicitly admitted infrastructure principals
         * @param externalBaseUri configured public ACME URL authority for JWS binding
         * @param maximumHeaderBytes bounded request-header bytes
         * @param maximumBodyBytes bounded JWS/CSR request body bytes
         * @param execution isolated protocol workers, queue, admission, and deadlines
         * @param validationExecution isolated challenge-validation workers and queue
         * @param nonceLifetime finite replay-nonce lifetime
         * @param maximumOutstandingNonces bounded process-local nonce population
         * @param maximumAccountsPresented bounded administrative account page size
         * @param maximumOrdersPresented bounded account order page size
         * @param admissionWindow finite in-memory rate window
         * @param maximumNewAccountsPerWindow bounded directory-wide account admission
         * @param maximumNewOrdersPerAccountWindow bounded per-account order admission
         * @param maximumPendingOrdersPerAccount bounded durable pending-order population
         * @param maximumChallengeValidationsPerAccountWindow bounded validation admission
         * @param maximumConcurrentFinalizations bounded listener-wide finalization concurrency
         * @param challengeProviders explicitly enabled provider configurations
         * @param eabProviders explicitly enabled secret-confining EAB provider configurations
         * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
         * @throws NullPointerException if a required transport/execution value, duration, option container or
         *     copied collection element is null
         * @throws IllegalArgumentException if identity/port/origin, direct/proxy membership, provider list or
         *     numeric/duration/SDK constraints are invalid
         */
        public AcmeListener {
            Objects.requireNonNull(hybridSdk, HYBRID_SDK);
            hybridSdk.ifPresent(value -> value.requireBodyBudget(maximumBodyBytes));
            if (hybridSdk.isPresent() && !hybridSdk.orElseThrow().canonicalOrigin().equals(
                    externalBaseUri.toString() + (externalBaseUri.getPort() < 0 ? ":443" : ""))) {
                throw new IllegalArgumentException("SDK_ORIGIN_DIFFERS_FROM_ACME_ORIGIN");
            }
            Permission.requireId(listenerId, "ACME listener");
            Objects.requireNonNull(address, ADDRESS);
            if (port < 0 || port > 65_535) {
                throw new IllegalArgumentException("ACME listener port is invalid");
            }
            Objects.requireNonNull(tlsProvider, TLS_PROVIDER);
            Objects.requireNonNull(transportMode, "transportMode");
            proxyTransportMappings = List.copyOf(Objects.requireNonNull(proxyTransportMappings,
                    "proxyTransportMappings"));
            trustedProxyPrincipalIds = Set.copyOf(Objects.requireNonNull(trustedProxyPrincipalIds,
                    "trustedProxyPrincipalIds"));
            trustedProxyPrincipalIds.forEach(Permission::requirePrincipal);
            externalBaseUri = Objects.requireNonNull(externalBaseUri, "externalBaseUri");
            if (!"https".equalsIgnoreCase(externalBaseUri.getScheme()) || externalBaseUri.getHost() == null
                    || externalBaseUri.getUserInfo() != null || externalBaseUri.getQuery() != null
                    || externalBaseUri.getFragment() != null || !externalBaseUri.getPath().isEmpty()) {
                throw new IllegalArgumentException("ACME external base URI is invalid");
            }
            bounded(maximumHeaderBytes, 1_024, 1_048_576, "ACME header bound");
            bounded(maximumBodyBytes, AcmeWireBounds.minimumCompletionDocumentBytes(externalBaseUri),
                    StrictBounds.MAXIMUM_ACME_BODY, "ACME body bound");
            Objects.requireNonNull(execution, EXECUTION);
            Objects.requireNonNull(validationExecution, "validationExecution");
            positive(nonceLifetime, Duration.ofHours(1), "ACME nonce lifetime");
            bounded(maximumOutstandingNonces, 16, 1_000_000, "ACME nonce capacity");
            bounded(maximumAccountsPresented, 1, 256, "ACME account presentation limit");
            bounded(maximumOrdersPresented, 1, 256, "ACME order presentation limit");
            positive(admissionWindow, Duration.ofDays(1), "ACME admission window");
            bounded(maximumNewAccountsPerWindow, 1, 1_000_000, "ACME account rate");
            bounded(maximumNewOrdersPerAccountWindow, 1, 1_000_000, "ACME order rate");
            bounded(maximumPendingOrdersPerAccount, 1, 100_000, "ACME pending order bound");
            bounded(
                    maximumChallengeValidationsPerAccountWindow,
                    1,
                    1_000_000,
                    "ACME validation rate");
            bounded(maximumConcurrentFinalizations, 1, 10_000, "ACME finalization bound");
            challengeProviders = providers(challengeProviders, "challenge");
            eabProviders = providers(eabProviders, "EAB");
            if (transportMode == AcmeTransportMode.DIRECT_TLS
                    && (!proxyTransportMappings.isEmpty() || !trustedProxyPrincipalIds.isEmpty())) {
                throw new IllegalArgumentException(
                        "Direct ACME transport cannot configure proxy identity");
            }
            if (transportMode == AcmeTransportMode.TRUSTED_REVERSE_PROXY) {
                boolean mappingOutsideTrusted = false;
                for (ClientCertificateMapping mapping : proxyTransportMappings) {
                    if (!trustedProxyPrincipalIds.contains(mapping.principalId())) {
                        mappingOutsideTrusted = true;
                    }
                }
                if (proxyTransportMappings.isEmpty() || trustedProxyPrincipalIds.isEmpty()
                        || mappingOutsideTrusted
                        || !proxyTransportMappings.stream().map(ClientCertificateMapping::principalId)
                                .collect(java.util.stream.Collectors.toUnmodifiableSet())
                                .equals(trustedProxyPrincipalIds)) {
                    throw new IllegalArgumentException(
                            "ACME trusted-proxy transport is incomplete");
                }
            }
        }

        /**
         * Returns the listener socket address.
         *
         * @return exact listener socket address
         */
        public InetSocketAddress socketAddress() { return new InetSocketAddress(address, port); }

        private static List<ProviderConfig> providers(List<ProviderConfig> source, String name) {
            List<ProviderConfig> values = List.copyOf(Objects.requireNonNull(source, name));
            if (values.size() > 64 || values.stream().map(ProviderConfig::backendId).distinct().count() != values.size()) {
                throw new IllegalArgumentException(
                        "ACME " + name + " provider identities are invalid");
            }
            return values;
        }
    }

    /**
     * Separately bounded EST protocol listener configuration.
     *
     * @param listenerId  stable process-local listener identity
     * @param address     canonical bind address
     * @param port        TCP port, including zero for an ephemeral test listener
     * @param tlsProvider explicit server TLS identity provider
     * @param execution   isolated protocol workers, queue, admission, and deadlines
     * @param maximumHeaderBytes bounded request-header bytes
     * @param maximumBodyBytes   bounded request-body bytes (must accommodate a PKCS#10 CSR)
     * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
     */
    public record EstListener(String listenerId, InetAddress address, int port,
            ProviderConfig tlsProvider, Execution execution,
            int maximumHeaderBytes, int maximumBodyBytes, Optional<HybridSdkListener> hybridSdk) {
        /**
         * Preserves the SDK-disabled listener constructor.
         *
         * @param listenerId stable process-local listener identity
         * @param address canonical bind address
         * @param port TCP port, including zero for an ephemeral test listener
         * @param tlsProvider explicit server TLS identity provider
         * @param execution isolated protocol workers, queue, admission, and deadlines
         * @param maximumHeaderBytes bounded request-header bytes
         * @param maximumBodyBytes bounded request-body bytes (must accommodate a PKCS#10 CSR)
         * @throws NullPointerException if a required supplied configuration reference or container is null
         * @throws IllegalArgumentException if delegated local configuration constraints fail
         */
        public EstListener(String listenerId, InetAddress address, int port,
            ProviderConfig tlsProvider, Execution execution,
            int maximumHeaderBytes, int maximumBodyBytes) {
            this(listenerId, address, port, tlsProvider, execution, maximumHeaderBytes, maximumBodyBytes, Optional.empty());
        }

        /**
         * Checks the configured EST identity, bind/TLS/execution references and listener budgets.
         *
         * @param listenerId stable process-local listener identity
         * @param address canonical bind address
         * @param port TCP port, including zero for an ephemeral test listener
         * @param tlsProvider explicit server TLS identity provider
         * @param execution isolated protocol workers, queue, admission, and deadlines
         * @param maximumHeaderBytes bounded request-header bytes
         * @param maximumBodyBytes bounded request-body bytes (must accommodate a PKCS#10 CSR)
         * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
         * @throws NullPointerException if address, tlsProvider, execution or the SDK option container is null
         * @throws IllegalArgumentException if identity, port, header/body budget or optional SDK proof-envelope
         *     capacity is invalid
         */
        public EstListener {
            Objects.requireNonNull(hybridSdk, HYBRID_SDK);
            hybridSdk.ifPresent(value -> value.requireBodyBudget(maximumBodyBytes));
            Permission.requireId(listenerId, "EST listener");
            Objects.requireNonNull(address, ADDRESS);
            if (port < 0 || port > 65_535) {
                throw new IllegalArgumentException("EST listener port is invalid");
            }
            Objects.requireNonNull(tlsProvider, TLS_PROVIDER);
            Objects.requireNonNull(execution, EXECUTION);
            bounded(maximumHeaderBytes, 1_024, 1_048_576, "EST header bound");
            bounded(maximumBodyBytes, 1_024, 16_777_216, "EST body bound");
        }

        /**
         * Returns the listener socket address.
         *
         * @return exact socket address
         */
        public InetSocketAddress socketAddress() { return new InetSocketAddress(address, port); }
    }

    /**
     * Configuration for the optional SCEP RFC 8894 HTTPS listener.
     *
     * @param listenerId         stable process-local listener identity
     * @param address            canonical bind address
     * @param port               TCP port, including zero for an ephemeral test listener
     * @param tlsProvider        explicit server TLS identity provider
     * @param execution          isolated protocol workers, queue, admission, and deadlines
     * @param maximumHeaderBytes bounded request-header bytes
     * @param maximumBodyBytes   bounded request-body bytes
     * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
     */
    public record ScepListener(String listenerId, InetAddress address, int port,
            ProviderConfig tlsProvider, Execution execution,
            int maximumHeaderBytes, int maximumBodyBytes, Optional<HybridSdkListener> hybridSdk) {
        /**
         * Preserves the SDK-disabled listener constructor.
         *
         * @param listenerId stable process-local listener identity
         * @param address canonical bind address
         * @param port TCP port, including zero for an ephemeral test listener
         * @param tlsProvider explicit server TLS identity provider
         * @param execution isolated protocol workers, queue, admission, and deadlines
         * @param maximumHeaderBytes bounded request-header bytes
         * @param maximumBodyBytes bounded request-body bytes
         * @throws NullPointerException if a required supplied configuration reference or container is null
         * @throws IllegalArgumentException if delegated local configuration constraints fail
         */
        public ScepListener(String listenerId, InetAddress address, int port,
            ProviderConfig tlsProvider, Execution execution,
            int maximumHeaderBytes, int maximumBodyBytes) {
            this(listenerId, address, port, tlsProvider, execution, maximumHeaderBytes, maximumBodyBytes, Optional.empty());
        }

        /**
         * Checks the configured SCEP identity, bind/TLS/execution references and listener budgets.
         *
         * @param listenerId stable process-local listener identity
         * @param address canonical bind address
         * @param port TCP port, including zero for an ephemeral test listener
         * @param tlsProvider explicit server TLS identity provider
         * @param execution isolated protocol workers, queue, admission, and deadlines
         * @param maximumHeaderBytes bounded request-header bytes
         * @param maximumBodyBytes bounded request-body bytes
         * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
         * @throws NullPointerException if address, tlsProvider, execution or the SDK option container is null
         * @throws IllegalArgumentException if identity, port, header/body budget or optional SDK proof-envelope
         *     capacity is invalid
         */
        public ScepListener {
            Objects.requireNonNull(hybridSdk, HYBRID_SDK);
            hybridSdk.ifPresent(value -> value.requireBodyBudget(maximumBodyBytes));
            Permission.requireId(listenerId, "SCEP listener");
            Objects.requireNonNull(address, ADDRESS);
            if (port < 0 || port > 65_535) {
                throw new IllegalArgumentException("SCEP listener port is invalid");
            }
            Objects.requireNonNull(tlsProvider, TLS_PROVIDER);
            Objects.requireNonNull(execution, EXECUTION);
            bounded(maximumHeaderBytes, 1_024, 1_048_576, "SCEP header bound");
            bounded(maximumBodyBytes, 1_024, 16_777_216, "SCEP body bound");
        }

        /**
         * Returns the listener socket address.
         *
         * @return exact socket address
         */
        public InetSocketAddress socketAddress() { return new InetSocketAddress(address, port); }
    }

    /**
     * Configuration for the optional CMP RFC 4210/9480 HTTPS listener.
     *
     * @param listenerId         stable process-local listener identity
     * @param address            canonical bind address
     * @param port               TCP port, including zero for an ephemeral test listener
     * @param tlsProvider        explicit server TLS identity provider
     * @param execution          isolated protocol workers, queue, admission, and deadlines
     * @param maximumHeaderBytes bounded request-header bytes
     * @param maximumBodyBytes   bounded request-body bytes
     * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
     */
    public record CmpListener(String listenerId, InetAddress address, int port,
            ProviderConfig tlsProvider, Execution execution,
            int maximumHeaderBytes, int maximumBodyBytes, Optional<HybridSdkListener> hybridSdk) {
        /**
         * Preserves the SDK-disabled listener constructor.
         *
         * @param listenerId stable process-local listener identity
         * @param address canonical bind address
         * @param port TCP port, including zero for an ephemeral test listener
         * @param tlsProvider explicit server TLS identity provider
         * @param execution isolated protocol workers, queue, admission, and deadlines
         * @param maximumHeaderBytes bounded request-header bytes
         * @param maximumBodyBytes bounded request-body bytes
         * @throws NullPointerException if a required supplied configuration reference or container is null
         * @throws IllegalArgumentException if delegated local configuration constraints fail
         */
        public CmpListener(String listenerId, InetAddress address, int port,
            ProviderConfig tlsProvider, Execution execution,
            int maximumHeaderBytes, int maximumBodyBytes) {
            this(listenerId, address, port, tlsProvider, execution, maximumHeaderBytes, maximumBodyBytes, Optional.empty());
        }

        /**
         * Checks the configured CMP identity, bind/TLS/execution references and listener budgets.
         *
         * @param listenerId stable process-local listener identity
         * @param address canonical bind address
         * @param port TCP port, including zero for an ephemeral test listener
         * @param tlsProvider explicit server TLS identity provider
         * @param execution isolated protocol workers, queue, admission, and deadlines
         * @param maximumHeaderBytes bounded request-header bytes
         * @param maximumBodyBytes bounded request-body bytes
         * @param hybridSdk explicit SDK opt-in, empty disables SDK routes
         * @throws NullPointerException if address, tlsProvider, execution or the SDK option container is null
         * @throws IllegalArgumentException if identity, port, header/body budget or optional SDK proof-envelope
         *     capacity is invalid
         */
        public CmpListener {
            Objects.requireNonNull(hybridSdk, HYBRID_SDK);
            hybridSdk.ifPresent(value -> value.requireBodyBudget(maximumBodyBytes));
            Permission.requireId(listenerId, "CMP listener");
            Objects.requireNonNull(address, ADDRESS);
            if (port < 0 || port > 65_535) {
                throw new IllegalArgumentException("CMP listener port is invalid");
            }
            Objects.requireNonNull(tlsProvider, TLS_PROVIDER);
            Objects.requireNonNull(execution, EXECUTION);
            bounded(maximumHeaderBytes, 1_024, 1_048_576, "CMP header bound");
            bounded(maximumBodyBytes, 1_024, 16_777_216, "CMP body bound");
        }

        /**
         * Returns the listener socket address.
         *
         * @return exact socket address
         */
        public InetSocketAddress socketAddress() { return new InetSocketAddress(address, port); }
    }

    /**
     * Process-local external capability references, with no secret resolution.
     *
     * <p>Environment names are syntax-checked. The optional publisher-store string is retained
     * without path validation, and store/password pairing is not enforced here. Required credential
     * availability and backend-specific policy remain startup/runtime checks. Generated record
     * diagnostics are not redaction.
     *
     * @param keyUnlockEnvironmentVariable optional keyring unlock environment variable
     * @param publisherSecretsStore optional path to the encrypted publisher secrets store
     * @param publisherSecretsEnvironmentVariable optional environment variable whose value is the
     *     store password; required for CLASSIC and HYBRID stores
     */
    // Component names are established public accessors.
    @SuppressWarnings("PMD.LongVariable")
    public record RuntimeCapabilities(
            Optional<String> keyUnlockEnvironmentVariable,
            Optional<String> publisherSecretsStore,
            Optional<String> publisherSecretsEnvironmentVariable) {
        /**
         * Checks optional environment-variable name syntax without reading secrets or validating store
         * contents.
         *
         * @param keyUnlockEnvironmentVariable optional keyring unlock environment variable
         * @param publisherSecretsStore optional path to the encrypted publisher secrets store
         * @param publisherSecretsEnvironmentVariable optional environment variable whose value is the
         *     publisher secrets-store password; no environment value is read by this constructor
         * @throws NullPointerException if an optional reference container is null
         * @throws IllegalArgumentException if a supplied environment-variable name is not uppercase ASCII with
         *     the permitted length/grammar
         */
        public RuntimeCapabilities {
            keyUnlockEnvironmentVariable =
                    Objects.requireNonNull(
                                    keyUnlockEnvironmentVariable, "keyUnlockEnvironmentVariable")
                            .map(
                                    value -> {
                                        if (!value.matches("[A-Z][A-Z0-9_]{0,127}")) {
                                            throw new IllegalArgumentException(
                                                    "Key-unlock environment reference is invalid");
                                        }
                                        return value;
                                    });
            publisherSecretsStore = Objects.requireNonNull(publisherSecretsStore,
                    "publisherSecretsStore");
            publisherSecretsEnvironmentVariable = Objects.requireNonNull(
                    publisherSecretsEnvironmentVariable,
                    "publisherSecretsEnvironmentVariable").map(value -> {
                        if (!value.matches("[A-Z][A-Z0-9_]{0,127}")) {
                            throw new IllegalArgumentException(
                                    "Publisher-secrets environment reference is invalid");
                        }
                        return value;
                    });
        }
    }

    /**
     * Bounds for one signing-reconciliation pass executed by {@code SigningReconciliationWorker}.
     *
     * @param maximumRecords maximum signing workflow records examined per pass
     * @param maximumProviderCalls maximum provider calls issued per pass
     * @param passTimeout maximum wall-clock duration of one reconciliation pass
     * @param providerCallTimeout maximum duration of a single provider call
     * @param idleInterval sleep duration between passes when there is no immediate work
     */
    public record SigningReconciliation(int maximumRecords, int maximumProviderCalls,
            Duration passTimeout, Duration providerCallTimeout, Duration idleInterval) {
        /**
         * Validates one reconciliation budget.
         *
         * @param maximumRecords number of records, from 1 to 4096
         * @param maximumProviderCalls provider calls, from 1 to maximumRecords
         * @param passTimeout positive duration no greater than five minutes
         * @param providerCallTimeout positive duration no greater than passTimeout
         * @param idleInterval positive duration no greater than five minutes
         * @throws NullPointerException if a duration is null
         * @throws IllegalArgumentException if a bound is exceeded
         */
        public SigningReconciliation {
            bounded(maximumRecords, 1, 4096, "signing reconciliation record count");
            bounded(
                    maximumProviderCalls,
                    1,
                    maximumRecords,
                    "signing reconciliation provider call count");
            positive(passTimeout, Duration.ofMinutes(5), "signing reconciliation pass timeout");
            positive(
                    providerCallTimeout,
                    passTimeout,
                    "signing reconciliation provider call timeout");
            positive(idleInterval, Duration.ofMinutes(5), "signing reconciliation idle interval");
        }

        /**
         * Returns the standard bounded reconciliation policy.
         *
         * @return a 256-record, 64-call budget with a 30-second pass timeout,
         * 10-second provider timeout and 2-second idle interval
         */
        public static SigningReconciliation defaults() {
            return new SigningReconciliation(256, 64, Duration.ofSeconds(30), Duration.ofSeconds(10),
                    Duration.ofSeconds(2));
        }
    }

    private static void bounded(int value, int minimum, int maximum, String name) {
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static void positive(Duration value, Duration maximum, String name) {
        Objects.requireNonNull(value, name);
        if (value.isZero() || value.isNegative() || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static void nonNegative(Duration value, Duration maximum, String name) {
        Objects.requireNonNull(value, name);
        if (value.isNegative() || value.compareTo(maximum) > 0) {
            throw new IllegalArgumentException(name + " is invalid");
        }
    }

    private static void requireDistinct(InetAddress firstAddress, int firstPort,
            InetAddress secondAddress, int secondPort, String message) {
        if (firstPort != 0 && firstPort == secondPort && (firstAddress.equals(secondAddress)
                || firstAddress.isAnyLocalAddress() || secondAddress.isAnyLocalAddress())) {
            throw new IllegalArgumentException(message);
        }
    }

    /** Fixed body bound shared by the standalone ACME listeners. */
    private static final class StrictBounds {
        private static final int MAXIMUM_ACME_BODY = 16_777_216;
    }

    /**
     * Explicit configured origin shared by version-one HTTP SDK sidepath opt-ins.
     *
     * <p>Administrative/enrollment routes retain their native authentication
     * boundaries; public OCSP additionally requires its separately configured TLS
     * listener and responder role opt-in. A canonical origin or adequate body
     * budget alone grants no authority and proves no response freshness.</p>
     *
     * @param canonicalOrigin configured canonical HTTPS origin including port
     */
    public record HybridSdkListener(String canonicalOrigin) {
        private static final int MINIMUM_SDK_BODY_BYTES = 16_384;

        /**
         * Checks the explicit canonical HTTPS origin without discovering or enabling a listener.
         *
         * @param canonicalOrigin configured canonical HTTPS origin including port
         * @throws IllegalArgumentException if the origin is not in the canonical HTTPS form with explicit port
         */
        public HybridSdkListener {
            zeroecho.pki.api.hybrid.sdk.HybridSdkFrame.requireOrigin(canonicalOrigin);
        }
        /**
         * Rejects a listener unable to carry the fixed-suite proof envelope.
         *
         * @param maximumBodyBytes existing listener wire budget
         * @throws IllegalArgumentException if the byte budget is below 16384
         */
        public void requireBodyBudget(int maximumBodyBytes) {
            if (maximumBodyBytes < MINIMUM_SDK_BODY_BYTES) {
                throw new IllegalArgumentException("SDK_BODY_BUDGET_TOO_SMALL");
            }
        }
    }
}
