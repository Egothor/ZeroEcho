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

import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory;
import zeroecho.pki.server.http.StrictJson;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.MetadataStoreId;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Strict current-version server configuration decoder with closed field sets.
 */
public final class PkiServerConfigurationCodec {
    private static final String IPV6_LOOPBACK_ALIAS = "::" + "1";
    private static final String EXECUTION = "execution";
    private static final String ADDRESS = "address";
    private static final String PORT = "port";
    private static final String TLS_PROVIDER = "tlsProvider";
    private static final String MAX_HEADER_BYTES = "maximumHeaderBytes";
    private static final String MAX_BODY_BYTES = "maximumBodyBytes";
    private static final String HYBRID_SDK = "hybridSdk";
    private static final String ENABLED = "enabled";
    private static final String LISTENER_ID = "listenerId";

    /**
     * Maximum server configuration document size.
     */
    public static final int MAXIMUM_CONFIGURATION_BYTES = 1_048_576;

    private PkiServerConfigurationCodec() {
    }

    /**
     * Reads and validates one exact configuration without opening providers,
     * stores, listeners, audit sinks, or sessions.
     *
     * @param path configuration path
     * @return immutable validated configuration
     * @throws IOException when the bounded file cannot be read
     * @throws IllegalArgumentException when framing or semantics are invalid
     */
    public static PkiServerConfiguration read(Path path) throws IOException {
        Path exact = path.toAbsolutePath().normalize();
        long size = Files.size(exact);
        if (size < 1 || size > MAXIMUM_CONFIGURATION_BYTES || Files.isSymbolicLink(exact)) {
            throw new IllegalArgumentException("Server configuration source is invalid");
        }
        return decode(Files.readAllBytes(exact));
    }

    /**
     * Decodes one bounded strict configuration document.
     *
     * @param document encoded configuration, bounded by {@link #MAXIMUM_CONFIGURATION_BYTES}
     * @return immutable validated server configuration
     * @throws IllegalArgumentException if framing, schema version, or semantics are invalid
     */
    public static PkiServerConfiguration decode(byte[] document) {
        ConfigurationFields root =
                ConfigurationFields.of(StrictJson.parse(document, MAXIMUM_CONFIGURATION_BYTES));
        root.allowed(
                Set.of(
                        "version",
                        "serverName",
                        "realm",
                        "listener",
                        "authentication",
                        EXECUTION,
                        "runtime",
                        "publicListener",
                        "acmeListener",
                        "estListener",
                        "scepListener",
                        "cmpListener",
                        "auditProjection"));
        int encodedVersion = root.integer("version");
        if (encodedVersion != PkiServerConfiguration.CURRENT_VERSION) {
            throw new IllegalArgumentException("Unsupported server schema version");
        }
        PkiServerConfiguration configuration =
                new PkiServerConfiguration(
                        PkiServerConfiguration.CURRENT_VERSION,
                        root.text("serverName"),
                        realm(root.object("realm")),
                        listener(root.object("listener")),
                        authentication(root.object("authentication")),
                        execution(root.object(EXECUTION)),
                        runtime(root.object("runtime")),
                        publicListener(root.object("publicListener")),
                        acmeListener(root.object("acmeListener")),
                        estListener(root.object("estListener")),
                        scepListener(root.object("scepListener")),
                        cmpListener(root.object("cmpListener")),
                        auditProjection(root.object("auditProjection")));
        root.complete();
        return configuration;
    }

    private static ServerRealmConfiguration realm(ConfigurationFields value) {
        value.allowed(
                Set.of(
                        "realmId",
                        "displayName",
                        "confirmationProof",
                        "authorityExposure",
                        "authorizationCommitment",
                        "approvalCommitment",
                        "extendedApprovalCommitment",
                        "disclosureCommitment",
                        "disclosureDefaults",
                        "controlLog",
                        "controlStoreId",
                        "approvalPolicy",
                        "issuanceSingleApprovalPolicy",
                        "issuanceThresholdApprovalPolicy",
                        "pkiSession",
                        "initialAdministratorPrincipalId"));
        AuthorityExposurePolicy exposure =
                ConfigurationRealmPolicies.exposure(value.object("authorityExposure"));
        ApprovalService.Policy approval = approval(value.object("approvalPolicy"));
        String approvalCommitment = value.text("approvalCommitment");
        if (!approval.commitment().equals(approvalCommitment)) {
            throw new IllegalArgumentException("Approval policy commitment does not match");
        }
        Map<ApprovalCategory, ApprovalService.Policy> approvalPolicies = new LinkedHashMap<>();
        approvalPolicies.put(ApprovalCategory.HIGH_RISK, approval);
        value.optionalObject("issuanceSingleApprovalPolicy").ifPresent(
                policy -> approvalPolicies.put(ApprovalCategory.ISSUANCE_SINGLE, approval(policy)));
        value.optionalObject("issuanceThresholdApprovalPolicy").ifPresent(
                policy -> approvalPolicies.put(ApprovalCategory.ISSUANCE_THRESHOLD, approval(policy)));
        String extendedCommitment = ServerRealmConfiguration.extendedApprovalCommitment(approvalPolicies);
        Optional<String> suppliedExtended = value.optionalText("extendedApprovalCommitment");
        if (approvalPolicies.size() > 1 && suppliedExtended.isEmpty()) {
            throw new IllegalArgumentException(
                    "Extended approval commitment is required when issuance approval policies are"
                        + " configured");
        }
        if (!extendedCommitment.equals(suppliedExtended.orElse(extendedCommitment))) {
            throw new IllegalArgumentException(
                    "Extended approval policy commitment does not match");
        }
        ServerRealmConfiguration result =
                new ServerRealmConfiguration(
                        new RealmId(value.text("realmId")),
                        value.text("displayName"),
                        ConfigurationRealmPolicies.confirmationProof(
                                value.object("confirmationProof")),
                        session(value.object("pkiSession")),
                        exposure,
                        value.text("authorizationCommitment"),
                        approvalCommitment,
                        extendedCommitment,
                        value.text("disclosureCommitment"),
                        ConfigurationRealmPolicies.disclosure(value.object("disclosureDefaults")),
                        Path.of(value.text("controlLog")),
                        new MetadataStoreId(value.text("controlStoreId")),
                        Map.copyOf(approvalPolicies),
                        value.optionalText("initialAdministratorPrincipalId"));
        value.complete();
        return result;
    }

    private static ApprovalService.Policy approval(ConfigurationFields value) {
        value.exact("policyId", "threshold", "eligibleApprovers", "requiredRoleTemplateIds",
                "requesterSeparation", "lifetimeMillis", "justificationRequired");
        ApprovalService.Policy result =
                new ApprovalService.Policy(
                        value.text("policyId"),
                        value.integer("threshold"),
                        strings(value.list("eligibleApprovers")),
                        strings(value.list("requiredRoleTemplateIds")),
                        value.bool("requesterSeparation"),
                        Duration.ofMillis(value.longValue("lifetimeMillis")),
                        value.bool("justificationRequired"));
        value.complete();
        return result;
    }

    private static PkiSessionConfiguration session(ConfigurationFields value) {
        Set<String> allowed =
                Set.of("version", "store", "audit", "signing", "publishers", "bindingProviders");
        value.allowed(allowed);
        int version = value.integer("version");
        ProviderConfig store = provider(value.object("store"));
        ProviderConfig audit = provider(value.object("audit"));
        Optional<PkiSessionConfiguration.SigningConfiguration> signing =
                value.optionalObject("signing").map(PkiServerConfigurationCodec::signing);
        List<ProviderConfig> publishers = new ArrayList<>();
        for (PkiOperationValue item : value.list("publishers")) {
            publishers.add(provider(ConfigurationFields.of(item)));
        }
        List<PkiSessionConfiguration.BindingProviderConfiguration> bindings = new ArrayList<>();
        for (PkiOperationValue item : value.list("bindingProviders")) {
            bindings.add(binding(ConfigurationFields.of(item)));
        }
        value.complete();
        return new PkiSessionConfiguration(version, store, audit, signing, publishers, bindings);
    }

    private static PkiSessionConfiguration.SigningConfiguration signing(ConfigurationFields value) {
        value.allowed(Set.of("provider", "signatureAlgorithm", "signingTtlMillis",
                "unlockEnvironmentVariable", "topology", "pureEdDsaMaximumTbsBytes"));
        Optional<Long> maximum = value.optionalLong("pureEdDsaMaximumTbsBytes");
        PkiSessionConfiguration.SigningConfiguration result = new PkiSessionConfiguration.SigningConfiguration(
                provider(value.object("provider")), value.text("signatureAlgorithm"),
                Duration.ofMillis(value.longValue("signingTtlMillis")),
                value.optionalText("unlockEnvironmentVariable"), topology(value.object("topology")),
                maximum.isPresent() ? java.util.OptionalLong.of(maximum.orElseThrow())
                        : java.util.OptionalLong.empty());
        value.complete();
        return result;
    }

    private static PkiSessionConfiguration.SigningTopology topology(ConfigurationFields value) {
        value.exact("coordinator", "exactGroups", "catchAll");
        ConfigurationFields limits = value.object("coordinator");
        limits.exact("pageSize", "claimLeaseMillis", "providerCallTimeoutMillis",
                "idlePollIntervalMillis", "closeTimeoutMillis");
        PkiSessionConfiguration.SigningCoordinatorLimits coordinator =
                new PkiSessionConfiguration.SigningCoordinatorLimits(limits.integer("pageSize"),
                        Duration.ofMillis(limits.longValue("claimLeaseMillis")),
                        Duration.ofMillis(limits.longValue("providerCallTimeoutMillis")),
                        Duration.ofMillis(limits.longValue("idlePollIntervalMillis")),
                        Duration.ofMillis(limits.longValue("closeTimeoutMillis")));
        limits.complete();
        List<PkiSessionConfiguration.SigningKeyGroup> groups = new ArrayList<>();
        for (PkiOperationValue item : value.list("exactGroups")) {
            appendSigningGroup(groups, item);
        }
        PkiSessionConfiguration.SigningTopology result = new PkiSessionConfiguration.SigningTopology(
                coordinator, groups, lanePool(value.object("catchAll")));
        value.complete();
        return result;
    }

    private static PkiSessionConfiguration.SigningLanePool lanePool(ConfigurationFields value) {
        value.exact("laneCount", "prefetchSize");
        PkiSessionConfiguration.SigningLanePool result = new PkiSessionConfiguration.SigningLanePool(
                value.integer("laneCount"), value.integer("prefetchSize"));
        value.complete();
        return result;
    }

    private static PkiSessionConfiguration.BindingProviderConfiguration binding(
            ConfigurationFields value) {
        value.allowed(Set.of("providerId", "authorizedOidRoots", "expectedBindingSetVersion"));
        PkiSessionConfiguration.BindingProviderConfiguration result =
                new PkiSessionConfiguration.BindingProviderConfiguration(value.text("providerId"),
                        List.copyOf(strings(value.list("authorizedOidRoots"))),
                        value.optionalText("expectedBindingSetVersion"));
        value.complete();
        return result;
    }

    private static ProviderConfig provider(ConfigurationFields value) {
        value.exact("id", "properties");
        ConfigurationFields properties = value.object("properties");
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, PkiOperationValue> item : properties.remaining().entrySet()) {
            result.put(item.getKey(), ConfigurationFields.text(item.getValue()));
        }
        properties.consumeAll();
        ProviderConfig provider = new ProviderConfig(value.text("id"), result);
        value.complete();
        return provider;
    }

    private static PkiServerConfiguration.Listener listener(ConfigurationFields value) {
        value.allowed(
                Set.of(
                        ADDRESS,
                        PORT,
                        TLS_PROVIDER,
                        "clientCertificateRequired",
                        MAX_HEADER_BYTES,
                        MAX_BODY_BYTES,
                        HYBRID_SDK));
        PkiServerConfiguration.Listener result =
                new PkiServerConfiguration.Listener(
                        address(value.text(ADDRESS)),
                        value.integer(PORT),
                        provider(value.object(TLS_PROVIDER)),
                        value.bool("clientCertificateRequired"),
                        value.integer(MAX_HEADER_BYTES),
                        value.integer(MAX_BODY_BYTES),
                        hybridSdk(value));
        value.complete();
        return result;
    }

    private static PkiServerConfiguration.Authentication authentication(ConfigurationFields value) {
        AdministrativeAuthenticationMode mode =
                AdministrativeAuthenticationMode.valueOf(value.text("mode"));
        if (mode == AdministrativeAuthenticationMode.DIRECT_MTLS) {
            value.exact("mode", "directClientMappings");
            List<PkiServerConfiguration.ClientCertificateMapping> direct = mappings(
                    value.list("directClientMappings"));
            value.complete();
            return new PkiServerConfiguration.Authentication(mode, direct, List.of(), List.of(), Set.of(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0);
        }
        value.allowed(
                Set.of(
                        "mode",
                        "proxyTransportMappings",
                        "forwardedClientMappings",
                        "trustedProxyPrincipalIds",
                        "forwardedCertificateFormat",
                        "forwardedCertificateHeaderName",
                        "forwardedCertificateChainHeaderName",
                        "administrativeClientTrust",
                        "maximumForwardedCertificateBytes",
                        "maximumForwardedChainBytes"));
        List<PkiServerConfiguration.ClientCertificateMapping> proxy =
                mappings(value.list("proxyTransportMappings"));
        List<PkiServerConfiguration.ClientCertificateMapping> forwarded = mappings(
                value.list("forwardedClientMappings"));
        PkiServerConfiguration.Authentication result =
                new PkiServerConfiguration.Authentication(
                        mode,
                        List.of(),
                        proxy,
                        forwarded,
                        Set.copyOf(strings(value.list("trustedProxyPrincipalIds"))),
                        Optional.of(
                                ForwardedCertificateFormat.valueOf(
                                        value.text("forwardedCertificateFormat"))),
                        Optional.of(value.text("forwardedCertificateHeaderName")),
                        value.optionalText("forwardedCertificateChainHeaderName"),
                        Optional.of(provider(value.object("administrativeClientTrust"))),
                        value.integer("maximumForwardedCertificateBytes"),
                        value.integer("maximumForwardedChainBytes"));
        value.complete();
        return result;
    }

    private static List<PkiServerConfiguration.ClientCertificateMapping> mappings(
            List<PkiOperationValue> source) {
        List<PkiServerConfiguration.ClientCertificateMapping> mappings = new ArrayList<>();
        for (PkiOperationValue item : source) {
            ConfigurationFields mapping = ConfigurationFields.of(item);
            mapping.allowed(Set.of("mappingId", "principalId", "certificateSha256",
                    "subjectPublicKeyInfoSha256", "issuerSerialSha256"));
            mappings.add(
                    new PkiServerConfiguration.ClientCertificateMapping(
                            mapping.text("mappingId"),
                            mapping.text("principalId"),
                            mapping.optionalText("certificateSha256"),
                            mapping.optionalText("subjectPublicKeyInfoSha256"),
                            mapping.optionalText("issuerSerialSha256")));
            mapping.complete();
        }
        return mappings;
    }

    private static PkiServerConfiguration.Execution execution(ConfigurationFields value) {
        value.exact("transportWorkers", "transportQueueCapacity", "operationWorkers",
                "operationQueueCapacity", "maximumAdmittedRequests", "defaultDeadlineMillis",
                "maximumDeadlineMillis", "gracefulShutdownMillis", "forcedShutdownMillis");
        PkiServerConfiguration.Execution result =
                new PkiServerConfiguration.Execution(
                        value.integer("transportWorkers"),
                        value.integer("transportQueueCapacity"),
                        value.integer("operationWorkers"),
                        value.integer("operationQueueCapacity"),
                        value.integer("maximumAdmittedRequests"),
                        Duration.ofMillis(value.longValue("defaultDeadlineMillis")),
                        Duration.ofMillis(value.longValue("maximumDeadlineMillis")),
                        Duration.ofMillis(value.longValue("gracefulShutdownMillis")),
                        Duration.ofMillis(value.longValue("forcedShutdownMillis")));
        value.complete();
        return result;
    }

    private static PkiServerConfiguration.AuditProjection auditProjection(
            ConfigurationFields value) {
        value.exact("maxRecords", "maxSinkCalls", "idleIntervalMillis");
        PkiServerConfiguration.AuditProjection result = new PkiServerConfiguration.AuditProjection(
                value.integer("maxRecords"), value.integer("maxSinkCalls"),
                Duration.ofMillis(value.longValue("idleIntervalMillis")));
        value.complete();
        return result;
    }

    private static Optional<PkiServerConfiguration.PublicListener> publicListener(
            ConfigurationFields value) {
        value.allowed(
                Set.of(
                        ENABLED,
                        ADDRESS,
                        PORT,
                        TLS_PROVIDER,
                        "allowPlaintextLoopback",
                        "authentication",
                        MAX_HEADER_BYTES,
                        MAX_BODY_BYTES,
                        EXECUTION,
                        "maximumStreamDurationMillis",
                        "publicImmutableCacheMillis",
                        "publicAliasCacheMillis",
                        "authorityListExposed",
                        "consoleBasePath",
                        HYBRID_SDK));
        if (!value.bool(ENABLED)) {
            value.exact(ENABLED);
            value.complete();
            return Optional.empty();
        }
        Optional<ProviderConfig> tlsProvider =
                value.optionalObject(TLS_PROVIDER).map(PkiServerConfigurationCodec::provider);
        PkiServerConfiguration.PublicListener result =
                new PkiServerConfiguration.PublicListener(
                        address(value.text(ADDRESS)),
                        value.integer(PORT),
                        tlsProvider,
                        value.bool("allowPlaintextLoopback"),
                        authentication(value.object("authentication")),
                        value.integer(MAX_HEADER_BYTES),
                        value.integer(MAX_BODY_BYTES),
                        execution(value.object(EXECUTION)),
                        Duration.ofMillis(value.longValue("maximumStreamDurationMillis")),
                        Duration.ofMillis(value.longValue("publicImmutableCacheMillis")),
                        Duration.ofMillis(value.longValue("publicAliasCacheMillis")),
                        value.bool("authorityListExposed"),
                        value.optionalText("consoleBasePath"),
                        hybridSdk(value));
        value.complete();
        return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.AcmeListener> acmeListener(
            ConfigurationFields value) {
        value.allowed(
                Set.of(
                        ENABLED,
                        LISTENER_ID,
                        ADDRESS,
                        PORT,
                        TLS_PROVIDER,
                        "transportMode",
                        "proxyTransportMappings",
                        "trustedProxyPrincipalIds",
                        "externalBaseUri",
                        MAX_HEADER_BYTES,
                        MAX_BODY_BYTES,
                        EXECUTION,
                        "validationExecution",
                        "nonceLifetimeMillis",
                        "maximumOutstandingNonces",
                        "maximumAccountsPresented",
                        "maximumOrdersPresented",
                        "admissionWindowMillis",
                        "maximumNewAccountsPerWindow",
                        "maximumNewOrdersPerAccountWindow",
                        "maximumPendingOrdersPerAccount",
                        "maximumChallengeValidationsPerAccountWindow",
                        "maximumConcurrentFinalizations",
                        "challengeProviders",
                        "eabProviders",
                        HYBRID_SDK));
        if (!value.bool(ENABLED)) {
            value.exact(ENABLED);
            value.complete();
            return Optional.empty();
        }
        PkiServerConfiguration.AcmeTransportMode mode = PkiServerConfiguration.AcmeTransportMode
                .valueOf(value.text("transportMode"));
        List<PkiServerConfiguration.ClientCertificateMapping> proxy = mode
                == PkiServerConfiguration.AcmeTransportMode.TRUSTED_REVERSE_PROXY
                        ? mappings(value.list("proxyTransportMappings")) : List.of();
        Set<String> trusted = mode == PkiServerConfiguration.AcmeTransportMode.TRUSTED_REVERSE_PROXY
                ? strings(value.list("trustedProxyPrincipalIds")) : Set.of();
        PkiServerConfiguration.AcmeListener result =
                new PkiServerConfiguration.AcmeListener(
                        value.text(LISTENER_ID),
                        address(value.text(ADDRESS)),
                        value.integer(PORT),
                        provider(value.object(TLS_PROVIDER)),
                        mode,
                        proxy,
                        trusted,
                        java.net.URI.create(value.text("externalBaseUri")),
                        value.integer(MAX_HEADER_BYTES),
                        value.integer(MAX_BODY_BYTES),
                        execution(value.object(EXECUTION)),
                        execution(value.object("validationExecution")),
                        Duration.ofMillis(value.longValue("nonceLifetimeMillis")),
                        value.integer("maximumOutstandingNonces"),
                        value.integer("maximumAccountsPresented"),
                        value.integer("maximumOrdersPresented"),
                        Duration.ofMillis(value.longValue("admissionWindowMillis")),
                        value.integer("maximumNewAccountsPerWindow"),
                        value.integer("maximumNewOrdersPerAccountWindow"),
                        value.integer("maximumPendingOrdersPerAccount"),
                        value.integer("maximumChallengeValidationsPerAccountWindow"),
                        value.integer("maximumConcurrentFinalizations"),
                        providers(value.list("challengeProviders")),
                        providers(value.list("eabProviders")),
                        hybridSdk(value));
        value.complete(); return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.EstListener> estListener(
            ConfigurationFields value) {
        value.allowed(
                Set.of(
                        ENABLED,
                        LISTENER_ID,
                        ADDRESS,
                        PORT,
                        TLS_PROVIDER,
                        EXECUTION,
                        MAX_HEADER_BYTES,
                        MAX_BODY_BYTES,
                        HYBRID_SDK));
        if (!value.bool(ENABLED)) {
            value.exact(ENABLED);
            value.complete();
            return Optional.empty();
        }
        PkiServerConfiguration.EstListener result =
                new PkiServerConfiguration.EstListener(
                        value.text(LISTENER_ID),
                        address(value.text(ADDRESS)),
                        value.integer(PORT),
                        provider(value.object(TLS_PROVIDER)),
                        execution(value.object(EXECUTION)),
                        value.integer(MAX_HEADER_BYTES),
                        value.integer(MAX_BODY_BYTES),
                        hybridSdk(value));
        value.complete(); return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.ScepListener> scepListener(
            ConfigurationFields value) {
        value.allowed(
                Set.of(
                        ENABLED,
                        LISTENER_ID,
                        ADDRESS,
                        PORT,
                        TLS_PROVIDER,
                        EXECUTION,
                        MAX_HEADER_BYTES,
                        MAX_BODY_BYTES,
                        HYBRID_SDK));
        if (!value.bool(ENABLED)) {
            value.exact(ENABLED);
            value.complete();
            return Optional.empty();
        }
        PkiServerConfiguration.ScepListener result =
                new PkiServerConfiguration.ScepListener(
                        value.text(LISTENER_ID),
                        address(value.text(ADDRESS)),
                        value.integer(PORT),
                        provider(value.object(TLS_PROVIDER)),
                        execution(value.object(EXECUTION)),
                        value.integer(MAX_HEADER_BYTES),
                        value.integer(MAX_BODY_BYTES),
                        hybridSdk(value));
        value.complete(); return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.CmpListener> cmpListener(
            ConfigurationFields value) {
        value.allowed(
                Set.of(
                        ENABLED,
                        LISTENER_ID,
                        ADDRESS,
                        PORT,
                        TLS_PROVIDER,
                        EXECUTION,
                        MAX_HEADER_BYTES,
                        MAX_BODY_BYTES,
                        HYBRID_SDK));
        if (!value.bool(ENABLED)) {
            value.exact(ENABLED);
            value.complete();
            return Optional.empty();
        }
        PkiServerConfiguration.CmpListener result =
                new PkiServerConfiguration.CmpListener(
                        value.text(LISTENER_ID),
                        address(value.text(ADDRESS)),
                        value.integer(PORT),
                        provider(value.object(TLS_PROVIDER)),
                        execution(value.object(EXECUTION)),
                        value.integer(MAX_HEADER_BYTES),
                        value.integer(MAX_BODY_BYTES),
                        hybridSdk(value));
        value.complete(); return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.HybridSdkListener> hybridSdk(
            ConfigurationFields value) {
        Optional<ConfigurationFields> configured = value.optionalObject(HYBRID_SDK);
        if (configured.isEmpty()) {
            return Optional.empty();
        }
        ConfigurationFields sdk = configured.orElseThrow();
        sdk.exact("canonicalOrigin");
        PkiServerConfiguration.HybridSdkListener result =
                new PkiServerConfiguration.HybridSdkListener(sdk.text("canonicalOrigin"));
        sdk.complete(); return Optional.of(result);
    }

    private static List<ProviderConfig> providers(List<PkiOperationValue> source) {
        List<ProviderConfig> result = new ArrayList<>();
        for (PkiOperationValue item : source) {
            result.add(provider(ConfigurationFields.of(item)));
        }
        return List.copyOf(result);
    }

    private static PkiServerConfiguration.RuntimeCapabilities runtime(ConfigurationFields value) {
        value.allowed(Set.of("keyUnlockEnvironmentVariable",
                "publisherSecretsStore", "publisherSecretsEnvironmentVariable"));
        PkiServerConfiguration.RuntimeCapabilities result = new PkiServerConfiguration.RuntimeCapabilities(
                value.optionalText("keyUnlockEnvironmentVariable"),
                value.optionalText("publisherSecretsStore"),
                value.optionalText("publisherSecretsEnvironmentVariable"));
        value.complete();
        return result;
    }

    // Listener parse failures retain the stable diagnostic without untrusted resolver details.
    @SuppressWarnings("PMD.PreserveStackTrace")
    private static InetAddress address(String value) {
        if (!value.matches("[0-9A-Fa-f:.]{2,64}") || value.contains("..")) {
            throw new IllegalArgumentException("Listener address must be a canonical IP literal");
        }
        try {
            InetAddress result = InetAddress.getByName(value);
            if (!result.getHostAddress().equalsIgnoreCase(value)
                    && !(result.isLoopbackAddress() && IPV6_LOOPBACK_ALIAS.equals(value))) {
                throw new IllegalArgumentException("Listener address is not canonical");
            }
            return result;
        } catch (UnknownHostException failure) {
            throw new IllegalArgumentException("Listener address is invalid");
        }
    }

    private static Set<String> strings(List<PkiOperationValue> values) {
        Set<String> result = new LinkedHashSet<>();
        for (PkiOperationValue value : values) {
            if (!result.add(ConfigurationFields.text(value))) {
                throw new IllegalArgumentException("Duplicate string value");
            }
        }
        return Set.copyOf(result);
    }

    private static zeroecho.pki.api.KeyRef configuredKeyRef(PkiOperationValue key) {
        return new zeroecho.pki.api.KeyRef(ConfigurationFields.text(key));
    }

    private static void appendSigningGroup(
            List<PkiSessionConfiguration.SigningKeyGroup> groups, PkiOperationValue item) {
        ConfigurationFields group = ConfigurationFields.of(item);
        group.exact("keyRefs", "lanePool");
        List<zeroecho.pki.api.KeyRef> keys = new ArrayList<>();
        for (PkiOperationValue key : group.list("keyRefs")) {
            keys.add(configuredKeyRef(key));
            }
        groups.add(
                new PkiSessionConfiguration.SigningKeyGroup(
                        keys, lanePool(group.object("lanePool"))));
        group.complete();
    }
}
