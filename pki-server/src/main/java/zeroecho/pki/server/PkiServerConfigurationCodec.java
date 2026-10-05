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

import zeroecho.pki.api.PkiId;
import zeroecho.pki.application.CredentialConfirmationProofAudience;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory;
import zeroecho.pki.server.http.StrictJson;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Strict current-version server configuration decoder with closed field sets. */
@SuppressWarnings("PMD")
public final class PkiServerConfigurationCodec {
    /** Maximum server configuration document size. */
    public static final int MAXIMUM_CONFIGURATION_BYTES = 1_048_576;
    private static final long DEFAULT_CONFIRMATION_CHALLENGE_TTL_MILLIS = 300_000L;
    private static final int DEFAULT_CONFIRMATION_RSA_MAXIMUM_MODULUS_BITS = 8_192;

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
        Fields root = Fields.of(StrictJson.parse(document, MAXIMUM_CONFIGURATION_BYTES));
        root.allowed(Set.of("version", "serverName", "realm", "listener", "authentication", "execution",
                "runtime", "publicListener", "acmeListener", "estListener", "scepListener", "cmpListener",
                "auditProjection"));
        int encodedVersion = root.integer("version");
        if (encodedVersion != PkiServerConfiguration.CURRENT_VERSION) {
            throw new IllegalArgumentException("Unsupported server schema version");
        }
        PkiServerConfiguration configuration = new PkiServerConfiguration(PkiServerConfiguration.CURRENT_VERSION,
                root.text("serverName"), realm(root.object("realm")), listener(root.object("listener")),
                authentication(root.object("authentication")), execution(root.object("execution")),
                runtime(root.object("runtime")), publicListener(root.object("publicListener")),
                acmeListener(root.object("acmeListener")), estListener(root.object("estListener")),
                scepListener(root.object("scepListener")), cmpListener(root.object("cmpListener")),
                auditProjection(root.object("auditProjection")));
        root.complete();
        return configuration;
    }

    private static ServerRealmConfiguration realm(Fields value) {
        value.allowed(Set.of("realmId", "displayName", "confirmationProof", "authorityExposure",
                "authorizationCommitment", "approvalCommitment", "extendedApprovalCommitment",
                "disclosureCommitment", "disclosureDefaults", "controlLog", "controlStoreId", "approvalPolicy",
                "issuanceSingleApprovalPolicy", "issuanceThresholdApprovalPolicy", "pkiSession"));
        AuthorityExposurePolicy exposure = exposure(value.object("authorityExposure"));
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
                    "Extended approval commitment is required when issuance approval policies are configured");
        }
        if (!extendedCommitment.equals(suppliedExtended.orElse(extendedCommitment))) {
            throw new IllegalArgumentException("Extended approval policy commitment does not match");
        }
        ServerRealmConfiguration result = new ServerRealmConfiguration(new RealmId(value.text("realmId")),
                value.text("displayName"), confirmationProof(value.object("confirmationProof")),
                session(value.object("pkiSession")), exposure,
                value.text("authorizationCommitment"), approvalCommitment, extendedCommitment,
                value.text("disclosureCommitment"),
                disclosure(value.object("disclosureDefaults")), Path.of(value.text("controlLog")),
                new MetadataStoreId(value.text("controlStoreId")), Map.copyOf(approvalPolicies));
        value.complete();
        return result;
    }

    private static CredentialConfirmationProofPolicy confirmationProof(Fields value) {
        value.allowed(Set.of("audience", "challengeTtlMillis", "rsaMaximumModulusBits"));
        long ttlMillis = value.optionalLong("challengeTtlMillis")
                .orElse(DEFAULT_CONFIRMATION_CHALLENGE_TTL_MILLIS);
        if (ttlMillis % 1_000L != 0L) {
            throw new IllegalArgumentException(
                    "Credential confirmation proof TTL must be a whole number of seconds");
        }
        CredentialConfirmationProofPolicy result = new CredentialConfirmationProofPolicy(
                new CredentialConfirmationProofAudience(value.text("audience")),
                Duration.ofMillis(ttlMillis), value.optionalInteger("rsaMaximumModulusBits")
                        .orElse(DEFAULT_CONFIRMATION_RSA_MAXIMUM_MODULUS_BITS));
        value.complete();
        return result;
    }

    private static AuthorityExposurePolicy exposure(Fields value) {
        value.exact("mode", "authorityIds", "creationPermitted");
        Set<PkiId> authorities = new LinkedHashSet<>();
        for (PkiOperationValue item : value.list("authorityIds")) authorities.add(new PkiId(Fields.text(item)));
        AuthorityExposurePolicy result = new AuthorityExposurePolicy(
                AuthorityExposurePolicy.Mode.valueOf(value.text("mode")), authorities,
                value.bool("creationPermitted"));
        value.complete();
        return result;
    }

    private static ApprovalService.Policy approval(Fields value) {
        value.exact("policyId", "threshold", "eligibleApprovers", "requiredRoleTemplateIds",
                "requesterSeparation", "lifetimeMillis", "justificationRequired");
        ApprovalService.Policy result = new ApprovalService.Policy(value.text("policyId"),
                value.integer("threshold"), strings(value.list("eligibleApprovers")),
                strings(value.list("requiredRoleTemplateIds")), value.bool("requesterSeparation"),
                Duration.ofMillis(value.longValue("lifetimeMillis")), value.bool("justificationRequired"));
        value.complete();
        return result;
    }

    private static DisclosureService.Defaults disclosure(Fields value) {
        value.exact("rootCa", "intermediateCa", "caChain", "crl", "leaf", "sensitiveLeaf");
        DisclosureService.Defaults result = new DisclosureService.Defaults(policy(value.text("rootCa")),
                policy(value.text("intermediateCa")), policy(value.text("caChain")), policy(value.text("crl")),
                policy(value.text("leaf")), policy(value.text("sensitiveLeaf")));
        value.complete();
        return result;
    }

    private static DisclosureService.Policy policy(String value) {
        return DisclosureService.Policy.valueOf(value);
    }

    private static PkiSessionConfiguration session(Fields value) {
        Set<String> allowed = Set.of("version", "store", "audit", "signing", "publishers", "bindingProviders");
        value.allowed(allowed);
        int version = value.integer("version");
        ProviderConfig store = provider(value.object("store"));
        ProviderConfig audit = provider(value.object("audit"));
        Optional<PkiSessionConfiguration.SigningConfiguration> signing = value.optionalObject("signing")
                .map(PkiServerConfigurationCodec::signing);
        List<ProviderConfig> publishers = new ArrayList<>();
        for (PkiOperationValue item : value.list("publishers")) publishers.add(provider(Fields.of(item)));
        List<PkiSessionConfiguration.BindingProviderConfiguration> bindings = new ArrayList<>();
        for (PkiOperationValue item : value.list("bindingProviders")) bindings.add(binding(Fields.of(item)));
        value.complete();
        return new PkiSessionConfiguration(version, store, audit, signing, publishers, bindings);
    }

    private static PkiSessionConfiguration.SigningConfiguration signing(Fields value) {
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

    private static PkiSessionConfiguration.SigningTopology topology(Fields value) {
        value.exact("coordinator", "exactGroups", "catchAll");
        Fields limits = value.object("coordinator");
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
            Fields group = Fields.of(item);
            group.exact("keyRefs", "lanePool");
            List<zeroecho.pki.api.KeyRef> keys = new ArrayList<>();
            for (PkiOperationValue key : group.list("keyRefs")) {
                keys.add(new zeroecho.pki.api.KeyRef(Fields.text(key)));
            }
            groups.add(new PkiSessionConfiguration.SigningKeyGroup(keys, lanePool(group.object("lanePool"))));
            group.complete();
        }
        PkiSessionConfiguration.SigningTopology result = new PkiSessionConfiguration.SigningTopology(
                coordinator, groups, lanePool(value.object("catchAll")));
        value.complete();
        return result;
    }

    private static PkiSessionConfiguration.SigningLanePool lanePool(Fields value) {
        value.exact("laneCount", "prefetchSize");
        PkiSessionConfiguration.SigningLanePool result = new PkiSessionConfiguration.SigningLanePool(
                value.integer("laneCount"), value.integer("prefetchSize"));
        value.complete();
        return result;
    }

    private static PkiSessionConfiguration.BindingProviderConfiguration binding(Fields value) {
        value.allowed(Set.of("providerId", "authorizedOidRoots", "expectedBindingSetVersion"));
        PkiSessionConfiguration.BindingProviderConfiguration result =
                new PkiSessionConfiguration.BindingProviderConfiguration(value.text("providerId"),
                        List.copyOf(strings(value.list("authorizedOidRoots"))),
                        value.optionalText("expectedBindingSetVersion"));
        value.complete();
        return result;
    }

    private static ProviderConfig provider(Fields value) {
        value.exact("id", "properties");
        Fields properties = value.object("properties");
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, PkiOperationValue> item : properties.remaining().entrySet()) {
            result.put(item.getKey(), Fields.text(item.getValue()));
        }
        properties.consumeAll();
        ProviderConfig provider = new ProviderConfig(value.text("id"), result);
        value.complete();
        return provider;
    }

    private static PkiServerConfiguration.Listener listener(Fields value) {
        value.exact("address", "port", "tlsProvider", "clientCertificateRequired", "maximumHeaderBytes",
                "maximumBodyBytes");
        PkiServerConfiguration.Listener result = new PkiServerConfiguration.Listener(
                address(value.text("address")), value.integer("port"), provider(value.object("tlsProvider")),
                value.bool("clientCertificateRequired"), value.integer("maximumHeaderBytes"),
                value.integer("maximumBodyBytes"));
        value.complete();
        return result;
    }

    private static PkiServerConfiguration.Authentication authentication(Fields value) {
        AdministrativeAuthenticationMode mode = AdministrativeAuthenticationMode.valueOf(value.text("mode"));
        if (mode == AdministrativeAuthenticationMode.DIRECT_MTLS) {
            value.exact("mode", "directClientMappings");
            List<PkiServerConfiguration.ClientCertificateMapping> direct = mappings(
                    value.list("directClientMappings"));
            value.complete();
            return new PkiServerConfiguration.Authentication(mode, direct, List.of(), List.of(), Set.of(),
                    Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty(), 0, 0);
        }
        value.allowed(Set.of("mode", "proxyTransportMappings", "forwardedClientMappings",
                "trustedProxyPrincipalIds", "forwardedCertificateFormat", "forwardedCertificateHeaderName",
                "forwardedCertificateChainHeaderName", "administrativeClientTrust",
                "maximumForwardedCertificateBytes", "maximumForwardedChainBytes"));
        List<PkiServerConfiguration.ClientCertificateMapping> proxy = mappings(value.list("proxyTransportMappings"));
        List<PkiServerConfiguration.ClientCertificateMapping> forwarded = mappings(
                value.list("forwardedClientMappings"));
        PkiServerConfiguration.Authentication result = new PkiServerConfiguration.Authentication(mode,
                List.of(), proxy, forwarded, Set.copyOf(strings(value.list("trustedProxyPrincipalIds"))),
                Optional.of(ForwardedCertificateFormat.valueOf(value.text("forwardedCertificateFormat"))),
                Optional.of(value.text("forwardedCertificateHeaderName")),
                value.optionalText("forwardedCertificateChainHeaderName"),
                Optional.of(provider(value.object("administrativeClientTrust"))),
                value.integer("maximumForwardedCertificateBytes"), value.integer("maximumForwardedChainBytes"));
        value.complete();
        return result;
    }

    private static List<PkiServerConfiguration.ClientCertificateMapping> mappings(
            List<PkiOperationValue> source) {
        List<PkiServerConfiguration.ClientCertificateMapping> mappings = new ArrayList<>();
        for (PkiOperationValue item : source) {
            Fields mapping = Fields.of(item);
            mapping.allowed(Set.of("mappingId", "principalId", "certificateSha256",
                    "subjectPublicKeyInfoSha256", "issuerSerialSha256"));
            mappings.add(new PkiServerConfiguration.ClientCertificateMapping(mapping.text("mappingId"),
                    mapping.text("principalId"), mapping.optionalText("certificateSha256"),
                    mapping.optionalText("subjectPublicKeyInfoSha256"),
                    mapping.optionalText("issuerSerialSha256")));
            mapping.complete();
        }
        return mappings;
    }

    private static PkiServerConfiguration.Execution execution(Fields value) {
        value.exact("transportWorkers", "transportQueueCapacity", "operationWorkers",
                "operationQueueCapacity", "maximumAdmittedRequests", "defaultDeadlineMillis",
                "maximumDeadlineMillis", "gracefulShutdownMillis", "forcedShutdownMillis");
        PkiServerConfiguration.Execution result = new PkiServerConfiguration.Execution(
                value.integer("transportWorkers"), value.integer("transportQueueCapacity"),
                value.integer("operationWorkers"), value.integer("operationQueueCapacity"),
                value.integer("maximumAdmittedRequests"), Duration.ofMillis(value.longValue("defaultDeadlineMillis")),
                Duration.ofMillis(value.longValue("maximumDeadlineMillis")),
                Duration.ofMillis(value.longValue("gracefulShutdownMillis")),
                Duration.ofMillis(value.longValue("forcedShutdownMillis")));
        value.complete();
        return result;
    }

    private static PkiServerConfiguration.AuditProjection auditProjection(Fields value) {
        value.exact("maxRecords", "maxSinkCalls", "idleIntervalMillis");
        PkiServerConfiguration.AuditProjection result = new PkiServerConfiguration.AuditProjection(
                value.integer("maxRecords"), value.integer("maxSinkCalls"),
                Duration.ofMillis(value.longValue("idleIntervalMillis")));
        value.complete();
        return result;
    }

    private static Optional<PkiServerConfiguration.PublicListener> publicListener(Fields value) {
        value.allowed(Set.of("enabled", "address", "port", "tlsProvider", "allowPlaintextLoopback", "authentication",
                "maximumHeaderBytes", "maximumBodyBytes", "execution", "maximumStreamDurationMillis",
                "publicImmutableCacheMillis",
                "publicAliasCacheMillis", "authorityListExposed"));
        if (!value.bool("enabled")) {
            value.exact("enabled");
            value.complete();
            return Optional.empty();
        }
        Optional<ProviderConfig> tlsProvider = value.optionalObject("tlsProvider")
                .map(PkiServerConfigurationCodec::provider);
        PkiServerConfiguration.PublicListener result = new PkiServerConfiguration.PublicListener(
                address(value.text("address")), value.integer("port"), tlsProvider,
                value.bool("allowPlaintextLoopback"), authentication(value.object("authentication")),
                value.integer("maximumHeaderBytes"), value.integer("maximumBodyBytes"),
                execution(value.object("execution")),
                Duration.ofMillis(value.longValue("maximumStreamDurationMillis")),
                Duration.ofMillis(value.longValue("publicImmutableCacheMillis")),
                Duration.ofMillis(value.longValue("publicAliasCacheMillis")),
                value.bool("authorityListExposed"));
        value.complete();
        return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.AcmeListener> acmeListener(Fields value) {
        value.allowed(Set.of("enabled", "listenerId", "address", "port", "tlsProvider", "transportMode",
                "proxyTransportMappings", "trustedProxyPrincipalIds", "externalBaseUri",
                "maximumHeaderBytes", "maximumBodyBytes", "execution", "validationExecution",
                "nonceLifetimeMillis", "maximumOutstandingNonces", "maximumAccountsPresented",
                "maximumOrdersPresented", "admissionWindowMillis", "maximumNewAccountsPerWindow",
                "maximumNewOrdersPerAccountWindow", "maximumPendingOrdersPerAccount",
                "maximumChallengeValidationsPerAccountWindow", "maximumConcurrentFinalizations",
                "challengeProviders", "eabProviders"));
        if (!value.bool("enabled")) {
            value.exact("enabled"); value.complete(); return Optional.empty();
        }
        PkiServerConfiguration.AcmeTransportMode mode = PkiServerConfiguration.AcmeTransportMode
                .valueOf(value.text("transportMode"));
        List<PkiServerConfiguration.ClientCertificateMapping> proxy = mode
                == PkiServerConfiguration.AcmeTransportMode.TRUSTED_REVERSE_PROXY
                        ? mappings(value.list("proxyTransportMappings")) : List.of();
        Set<String> trusted = mode == PkiServerConfiguration.AcmeTransportMode.TRUSTED_REVERSE_PROXY
                ? strings(value.list("trustedProxyPrincipalIds")) : Set.of();
        PkiServerConfiguration.AcmeListener result = new PkiServerConfiguration.AcmeListener(
                value.text("listenerId"), address(value.text("address")), value.integer("port"),
                provider(value.object("tlsProvider")), mode, proxy, trusted,
                java.net.URI.create(value.text("externalBaseUri")), value.integer("maximumHeaderBytes"),
                value.integer("maximumBodyBytes"), execution(value.object("execution")),
                execution(value.object("validationExecution")),
                Duration.ofMillis(value.longValue("nonceLifetimeMillis")),
                value.integer("maximumOutstandingNonces"), value.integer("maximumAccountsPresented"),
                value.integer("maximumOrdersPresented"), Duration.ofMillis(value.longValue("admissionWindowMillis")),
                value.integer("maximumNewAccountsPerWindow"),
                value.integer("maximumNewOrdersPerAccountWindow"), value.integer("maximumPendingOrdersPerAccount"),
                value.integer("maximumChallengeValidationsPerAccountWindow"),
                value.integer("maximumConcurrentFinalizations"), providers(value.list("challengeProviders")),
                providers(value.list("eabProviders")));
        value.complete(); return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.EstListener> estListener(Fields value) {
        value.allowed(Set.of("enabled", "listenerId", "address", "port", "tlsProvider",
                "execution", "maximumHeaderBytes", "maximumBodyBytes"));
        if (!value.bool("enabled")) {
            value.exact("enabled"); value.complete(); return Optional.empty();
        }
        PkiServerConfiguration.EstListener result = new PkiServerConfiguration.EstListener(
                value.text("listenerId"), address(value.text("address")), value.integer("port"),
                provider(value.object("tlsProvider")), execution(value.object("execution")),
                value.integer("maximumHeaderBytes"), value.integer("maximumBodyBytes"));
        value.complete(); return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.ScepListener> scepListener(Fields value) {
        value.allowed(Set.of("enabled", "listenerId", "address", "port", "tlsProvider",
                "execution", "maximumHeaderBytes", "maximumBodyBytes"));
        if (!value.bool("enabled")) {
            value.exact("enabled"); value.complete(); return Optional.empty();
        }
        PkiServerConfiguration.ScepListener result = new PkiServerConfiguration.ScepListener(
                value.text("listenerId"), address(value.text("address")), value.integer("port"),
                provider(value.object("tlsProvider")), execution(value.object("execution")),
                value.integer("maximumHeaderBytes"), value.integer("maximumBodyBytes"));
        value.complete(); return Optional.of(result);
    }

    private static Optional<PkiServerConfiguration.CmpListener> cmpListener(Fields value) {
        value.allowed(Set.of("enabled", "listenerId", "address", "port", "tlsProvider",
                "execution", "maximumHeaderBytes", "maximumBodyBytes"));
        if (!value.bool("enabled")) {
            value.exact("enabled"); value.complete(); return Optional.empty();
        }
        PkiServerConfiguration.CmpListener result = new PkiServerConfiguration.CmpListener(
                value.text("listenerId"), address(value.text("address")), value.integer("port"),
                provider(value.object("tlsProvider")), execution(value.object("execution")),
                value.integer("maximumHeaderBytes"), value.integer("maximumBodyBytes"));
        value.complete(); return Optional.of(result);
    }

    private static List<ProviderConfig> providers(List<PkiOperationValue> source) {
        List<ProviderConfig> result = new ArrayList<>();
        for (PkiOperationValue item : source) result.add(provider(Fields.of(item)));
        return List.copyOf(result);
    }

    private static PkiServerConfiguration.RuntimeCapabilities runtime(Fields value) {
        value.allowed(Set.of("keyUnlockEnvironmentVariable",
                "publisherSecretsStore", "publisherSecretsEnvironmentVariable"));
        PkiServerConfiguration.RuntimeCapabilities result = new PkiServerConfiguration.RuntimeCapabilities(
                value.optionalText("keyUnlockEnvironmentVariable"),
                value.optionalText("publisherSecretsStore"),
                value.optionalText("publisherSecretsEnvironmentVariable"));
        value.complete();
        return result;
    }

    private static InetAddress address(String value) {
        if (!value.matches("[0-9A-Fa-f:.]{2,64}") || value.contains("..")) {
            throw new IllegalArgumentException("Listener address must be a canonical IP literal");
        }
        try {
            InetAddress result = InetAddress.getByName(value);
            if (!result.getHostAddress().equalsIgnoreCase(value)
                    && !(result.isLoopbackAddress() && "::1".equals(value))) {
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
            if (!result.add(Fields.text(value))) throw new IllegalArgumentException("Duplicate string value");
        }
        return Set.copyOf(result);
    }

    /** Strict consumed-field view over one JSON object. */
    private static final class Fields {
        private final Map<String, PkiOperationValue> fields;
        private final Set<String> consumed = new LinkedHashSet<>();

        private Fields(Map<String, PkiOperationValue> fields) { this.fields = fields; }
        static Fields of(PkiOperationValue value) {
            if (!(value instanceof PkiOperationValue.ObjectValue object)) {
                throw new IllegalArgumentException("Configuration value must be an object");
            }
            return new Fields(object.fields());
        }
        void exact(String... names) { allowed(Set.of(names)); if (fields.size() != names.length)
            throw new IllegalArgumentException("Configuration fields are incomplete"); }
        void allowed(Set<String> names) { if (!names.containsAll(fields.keySet()))
            throw new IllegalArgumentException("Unknown configuration field"); }
        String text(String name) { consumed.add(name); return text(require(name)); }
        Optional<String> optionalText(String name) { if (!fields.containsKey(name)) return Optional.empty();
            return Optional.of(text(name)); }
        int integer(String name) { long value = longValue(name); return Math.toIntExact(value); }
        Optional<Integer> optionalInteger(String name) { return optionalLong(name).map(Math::toIntExact); }
        long longValue(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.IntegerValue integer)) throw type(); return integer.value(); }
        Optional<Long> optionalLong(String name) { if (!fields.containsKey(name)) return Optional.empty();
            return Optional.of(longValue(name)); }
        boolean bool(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.BooleanValue bool)) throw type(); return bool.value(); }
        Fields object(String name) { consumed.add(name); return of(require(name)); }
        Optional<Fields> optionalObject(String name) { if (!fields.containsKey(name)) return Optional.empty();
            return Optional.of(object(name)); }
        List<PkiOperationValue> list(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.ListValue list)) throw type(); return list.values(); }
        List<PkiOperationValue> optionalList(String name) { if (!fields.containsKey(name)) return List.of();
            return list(name); }
        Map<String, PkiOperationValue> remaining() { return fields; }
        void consumeAll() { consumed.addAll(fields.keySet()); }
        void complete() { if (!consumed.equals(fields.keySet())) throw new IllegalArgumentException(
                "Configuration fields were not consumed"); }
        private PkiOperationValue require(String name) { PkiOperationValue value = fields.get(name);
            if (value == null) throw new IllegalArgumentException("Required configuration field is missing");
            return value; }
        static String text(PkiOperationValue value) { if (!(value instanceof PkiOperationValue.Text text))
            throw type(); return text.value(); }
        private static IllegalArgumentException type() {
            return new IllegalArgumentException("Configuration field type is invalid");
        }
    }
}
