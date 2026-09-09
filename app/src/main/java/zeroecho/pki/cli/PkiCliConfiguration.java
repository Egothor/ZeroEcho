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
package zeroecho.pki.cli;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.application.PkiSessionConfiguration;
import zeroecho.pki.spi.ProviderConfig;

/** Strict versioned CLI configuration loader. */
final class PkiCliConfiguration {

    private static final int VERSION_ONE = 1;
    private static final int VERSION_TWO = 2;
    private static final int VERSION_THREE = 3;
    private static final int VERSION_FOUR = 4;
    private static final Set<String> ROOT_FIELDS_V1 = Set.of("version", "store", "audit");
    private static final Set<String> ROOT_FIELDS_V2 = Set.of("version", "store", "audit", "signing", "publishers");
    private static final Set<String> ROOT_FIELDS_V3 = Set.of("version", "store", "audit", "signing", "publishers",
            "bindingProviders");
    private static final Set<String> ROOT_FIELDS_V4 = ROOT_FIELDS_V3;
    private static final Set<String> PROVIDER_FIELDS = Set.of("provider", "properties");
    private static final Set<String> SIGNING_FIELDS = Set.of("workflow", "framework",
            "signatureAlgorithm", "signingTtlSeconds", "unlockEnvironmentVariable",
            "certificateSignatureBinding", "crlSignatureBinding", "subjectPublicKeyBinding",
            "laneCount", "queueCapacity", "gracefulDrainSeconds", "forcedCancellationSeconds",
            "signingServices", "caRouting");
    private static final Set<String> SIGNING_SERVICE_FIELDS = Set.of("serviceId", "workflow");
    private static final Set<String> SIGNING_REQUIRED_FIELDS = Set.of("workflow", "framework",
            "signatureAlgorithm", "signingTtlSeconds");
    private static final String STDOUT_PROVIDER = "stdout";

    private PkiCliConfiguration() {
    }

    /* default */ static PkiSessionConfiguration read(Path path) throws java.io.IOException {
        byte[] document = PkiCliFiles.readRegularFile(path, PkiCliJson.MAXIMUM_DOCUMENT_BYTES);
        PkiOperationValue.ObjectValue root = object(PkiCliJson.parse(document));
        int version = Math.toIntExact(integer(required(root, "version")));
        if (version == VERSION_ONE) {
            requireExactFields(root.fields(), ROOT_FIELDS_V1);
        } else if (version == VERSION_TWO) {
            requireFields(root.fields(), ROOT_FIELDS_V2);
        } else if (version == VERSION_THREE) {
            requireFields(root.fields(), ROOT_FIELDS_V3);
        } else if (version == VERSION_FOUR) {
            requireFields(root.fields(), ROOT_FIELDS_V4);
        } else {
            throw new IllegalArgumentException("Unsupported CLI configuration version");
        }
        ProviderConfig store = provider(required(root, "store"));
        ProviderConfig audit = provider(required(root, "audit"));
        if (STDOUT_PROVIDER.equals(audit.backendId())) {
            throw new IllegalArgumentException("CLI audit provider must not write to standard output");
        }
        if (version == VERSION_ONE) {
            return new PkiSessionConfiguration(version, store, audit);
        }
        java.util.Optional<PkiSessionConfiguration.SigningConfiguration> signing = java.util.Optional
                .ofNullable(root.fields().get("signing")).map(PkiCliConfiguration::signing);
        PkiOperationValue publisherValue = root.fields().get("publishers");
        List<ProviderConfig> publishers = publisherValue == null ? List.of()
                : list(publisherValue).values().stream().map(PkiCliConfiguration::provider).toList();
        PkiOperationValue bindingProviderValue = root.fields().get("bindingProviders");
        List<PkiSessionConfiguration.BindingProviderConfiguration> bindingProviders = bindingProviderValue == null
                ? List.of() : list(bindingProviderValue).values().stream()
                        .map(PkiCliConfiguration::bindingProvider).toList();
        return new PkiSessionConfiguration(version, store, audit, signing, publishers, bindingProviders);
    }

    private static void requireFields(Map<String, PkiOperationValue> actual, Set<String> allowed) {
        if (!actual.keySet().containsAll(ROOT_FIELDS_V1) || !allowed.containsAll(actual.keySet())) {
            throw new IllegalArgumentException("CLI document fields are invalid");
        }
    }

    private static PkiSessionConfiguration.BindingProviderConfiguration bindingProvider(PkiOperationValue value) {
        PkiOperationValue.ObjectValue object = object(value);
        Set<String> fields = object.fields().keySet();
        if (!fields.containsAll(Set.of("providerId", "authorizedOidRoots"))
                || !Set.of("providerId", "authorizedOidRoots", "expectedBindingSetVersion").containsAll(fields)) {
            throw new IllegalArgumentException("Binding-provider configuration fields are invalid");
        }
        List<String> roots = list(required(object, "authorizedOidRoots")).values().stream()
                .map(PkiCliConfiguration::text).toList();
        PkiOperationValue expected = object.fields().get("expectedBindingSetVersion");
        return new PkiSessionConfiguration.BindingProviderConfiguration(text(required(object, "providerId")), roots,
                expected == null ? java.util.Optional.empty() : java.util.Optional.of(text(expected)));
    }

    private static PkiSessionConfiguration.SigningConfiguration signing(PkiOperationValue value) {
        PkiOperationValue.ObjectValue object = object(value);
        if (!object.fields().keySet().containsAll(SIGNING_REQUIRED_FIELDS)
                || !SIGNING_FIELDS.containsAll(object.fields().keySet())) {
            throw new IllegalArgumentException("Signing configuration fields are invalid");
        }
        PkiOperationValue servicesValue = object.fields().get("signingServices");
        List<PkiSessionConfiguration.SigningServiceConfiguration> signingServices = servicesValue == null
                ? List.of()
                : list(servicesValue).values().stream().map(PkiCliConfiguration::signingService).toList();
        PkiOperationValue routingValue = object.fields().get("caRouting");
        Map<String, String> caRouting = new LinkedHashMap<>();
        if (routingValue != null) {
            for (Map.Entry<String, PkiOperationValue> entry : object(routingValue).fields().entrySet()) {
                caRouting.put(entry.getKey(), text(entry.getValue()));
            }
        }
        return new PkiSessionConfiguration.SigningConfiguration(provider(required(object, "workflow")),
                provider(required(object, "framework")), text(required(object, "signatureAlgorithm")),
                Duration.ofSeconds(integer(required(object, "signingTtlSeconds"))),
                optionalText(object, "unlockEnvironmentVariable"),
                optionalText(object, "certificateSignatureBinding"), optionalText(object, "crlSignatureBinding"),
                optionalText(object, "subjectPublicKeyBinding"),
                optionalInteger(object, "laneCount",
                        PkiSessionConfiguration.SigningConfiguration.DEFAULT_LANE_COUNT),
                optionalInteger(object, "queueCapacity",
                        PkiSessionConfiguration.SigningConfiguration.DEFAULT_QUEUE_CAPACITY),
                Duration.ofSeconds(optionalLong(object, "gracefulDrainSeconds",
                        PkiSessionConfiguration.SigningConfiguration.DEFAULT_GRACEFUL_DRAIN.toSeconds())),
                Duration.ofSeconds(optionalLong(object, "forcedCancellationSeconds",
                        PkiSessionConfiguration.SigningConfiguration.DEFAULT_FORCED_CANCELLATION.toSeconds())),
                List.copyOf(signingServices), Map.copyOf(caRouting));
    }

    private static PkiSessionConfiguration.SigningServiceConfiguration signingService(PkiOperationValue value) {
        PkiOperationValue.ObjectValue object = object(value);
        requireExactFields(object.fields(), SIGNING_SERVICE_FIELDS);
        return new PkiSessionConfiguration.SigningServiceConfiguration(text(required(object, "serviceId")),
                provider(required(object, "workflow")));
    }

    private static int optionalInteger(PkiOperationValue.ObjectValue object, String name, int defaultValue) {
        return Math.toIntExact(optionalLong(object, name, defaultValue));
    }

    private static long optionalLong(PkiOperationValue.ObjectValue object, String name, long defaultValue) {
        PkiOperationValue value = object.fields().get(name);
        return value == null ? defaultValue : integer(value);
    }

    private static ProviderConfig provider(PkiOperationValue value) {
        PkiOperationValue.ObjectValue object = object(value);
        requireExactFields(object.fields(), PROVIDER_FIELDS);
        String provider = text(required(object, "provider"));
        PkiOperationValue.ObjectValue properties = object(required(object, "properties"));
        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, PkiOperationValue> entry : properties.fields().entrySet()) {
            result.put(entry.getKey(), text(entry.getValue()));
        }
        return new ProviderConfig(provider, result);
    }

    /* default */ static PkiOperationValue required(PkiOperationValue.ObjectValue object, String name) {
        PkiOperationValue value = object.fields().get(name);
        if (value == null) {
            throw new IllegalArgumentException("Required CLI field is missing");
        }
        return value;
    }

    /* default */ static PkiOperationValue.ObjectValue object(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.ObjectValue object) {
            return object;
        }
        throw new IllegalArgumentException("CLI field has the wrong type");
    }

    private static PkiOperationValue.ListValue list(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.ListValue list) {
            return list;
        }
        throw new IllegalArgumentException("CLI field has the wrong type");
    }

    /* default */ static String text(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.Text text) {
            return text.value();
        }
        throw new IllegalArgumentException("CLI field has the wrong type");
    }

    private static java.util.Optional<String> optionalText(PkiOperationValue.ObjectValue object, String field) {
        PkiOperationValue value = object.fields().get(field);
        return value == null ? java.util.Optional.empty() : java.util.Optional.of(text(value));
    }

    /* default */ static long integer(PkiOperationValue value) {
        if (value instanceof PkiOperationValue.IntegerValue integer) {
            return integer.value();
        }
        throw new IllegalArgumentException("CLI field has the wrong type");
    }

    /* default */ static void requireExactFields(Map<String, PkiOperationValue> actual, Set<String> expected) {
        if (!actual.keySet().equals(expected)) {
            throw new IllegalArgumentException("CLI document fields are invalid");
        }
    }
}
