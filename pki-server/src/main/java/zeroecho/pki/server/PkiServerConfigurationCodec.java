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
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory;
import zeroecho.pki.server.http.StrictJson;
import zeroecho.pki.spi.ProviderConfig;
import zeroecho.pki.spi.store.MetadataStoreId;

/** Strict version-one server configuration decoder with closed field sets. */
@SuppressWarnings("PMD")
public final class PkiServerConfigurationCodec {
    /** Maximum server configuration document size. */
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

    /** Decodes one bounded strict configuration document. */
    public static PkiServerConfiguration decode(byte[] document) {
        Fields root = Fields.of(StrictJson.parse(document, MAXIMUM_CONFIGURATION_BYTES));
        root.exact("version", "serverName", "realm", "listener", "authentication", "execution", "runtime");
        PkiServerConfiguration configuration = new PkiServerConfiguration(root.integer("version"),
                root.text("serverName"), realm(root.object("realm")), listener(root.object("listener")),
                authentication(root.object("authentication")), execution(root.object("execution")),
                runtime(root.object("runtime")));
        root.complete();
        return configuration;
    }

    private static ServerRealmConfiguration realm(Fields value) {
        value.exact("realmId", "displayName", "authorityExposure", "authorizationCommitment",
                "approvalCommitment", "disclosureCommitment", "disclosureDefaults", "controlLog",
                "controlStoreId", "approvalPolicy", "pkiSession");
        AuthorityExposurePolicy exposure = exposure(value.object("authorityExposure"));
        ApprovalService.Policy approval = approval(value.object("approvalPolicy"));
        String approvalCommitment = value.text("approvalCommitment");
        if (!approval.commitment().equals(approvalCommitment)) {
            throw new IllegalArgumentException("Approval policy commitment does not match");
        }
        ServerRealmConfiguration result = new ServerRealmConfiguration(new RealmId(value.text("realmId")),
                value.text("displayName"), session(value.object("pkiSession")), exposure,
                value.text("authorizationCommitment"), approvalCommitment, value.text("disclosureCommitment"),
                disclosure(value.object("disclosureDefaults")), Path.of(value.text("controlLog")),
                new MetadataStoreId(value.text("controlStoreId")), Map.of(ApprovalCategory.HIGH_RISK, approval));
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
        Set<String> allowed = Set.of("workflow", "framework", "busPath", "signatureAlgorithm",
                "signingTtlMillis", "unlockEnvironmentVariable", "certificateSignatureBinding",
                "crlSignatureBinding", "subjectPublicKeyBinding");
        value.allowed(allowed);
        PkiSessionConfiguration.SigningConfiguration result = new PkiSessionConfiguration.SigningConfiguration(
                provider(value.object("workflow")), provider(value.object("framework")), value.text("busPath"),
                value.text("signatureAlgorithm"), Duration.ofMillis(value.longValue("signingTtlMillis")),
                value.optionalText("unlockEnvironmentVariable"), value.optionalText("certificateSignatureBinding"),
                value.optionalText("crlSignatureBinding"), value.optionalText("subjectPublicKeyBinding"));
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
        value.exact("mappings");
        List<PkiServerConfiguration.ClientCertificateMapping> mappings = new ArrayList<>();
        for (PkiOperationValue item : value.list("mappings")) {
            Fields mapping = Fields.of(item);
            mapping.allowed(Set.of("mappingId", "principalId", "certificateSha256",
                    "subjectPublicKeyInfoSha256", "issuerSerialSha256"));
            mappings.add(new PkiServerConfiguration.ClientCertificateMapping(mapping.text("mappingId"),
                    mapping.text("principalId"), mapping.optionalText("certificateSha256"),
                    mapping.optionalText("subjectPublicKeyInfoSha256"),
                    mapping.optionalText("issuerSerialSha256")));
            mapping.complete();
        }
        value.complete();
        return new PkiServerConfiguration.Authentication(mappings);
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

    private static PkiServerConfiguration.RuntimeCapabilities runtime(Fields value) {
        value.allowed(Set.of("keyUnlockEnvironmentVariable"));
        PkiServerConfiguration.RuntimeCapabilities result = new PkiServerConfiguration.RuntimeCapabilities(
                value.optionalText("keyUnlockEnvironmentVariable"));
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
        long longValue(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.IntegerValue integer)) throw type(); return integer.value(); }
        boolean bool(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.BooleanValue bool)) throw type(); return bool.value(); }
        Fields object(String name) { consumed.add(name); return of(require(name)); }
        Optional<Fields> optionalObject(String name) { if (!fields.containsKey(name)) return Optional.empty();
            return Optional.of(object(name)); }
        List<PkiOperationValue> list(String name) { consumed.add(name); PkiOperationValue value = require(name);
            if (!(value instanceof PkiOperationValue.ListValue list)) throw type(); return list.values(); }
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
