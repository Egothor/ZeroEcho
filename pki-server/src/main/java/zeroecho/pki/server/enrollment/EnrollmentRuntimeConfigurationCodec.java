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

package zeroecho.pki.server.enrollment;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import zeroecho.pki.application.PkiOperationValue;
import zeroecho.pki.server.http.StrictJson;

/** Closed bounded JSON projection for the separately versioned runtime companion. */
final class EnrollmentRuntimeConfigurationCodec {
    private static final int MAXIMUM_BYTES = 1_048_576;
    private EnrollmentRuntimeConfigurationCodec() { }

    /* default */ static EnrollmentRuntimeConfiguration read(Path path) throws IOException {
        try (InputStream input = Files.newInputStream(path)) {
            return decode(input.readNBytes(MAXIMUM_BYTES + 1));
        }
    }

    /* default */ static EnrollmentRuntimeConfiguration decode(byte[] bytes) {
        Map<String, PkiOperationValue> fields = object(StrictJson.parse(bytes, MAXIMUM_BYTES),
                Set.of("version", "budgets", "keyrings", "credentialSets", "activeCredentials"), Set.of("keygenArtifacts"));
        if (number(fields, "version") != EnrollmentRuntimeConfiguration.VERSION) {
            throw invalid();
        }
        return new EnrollmentRuntimeConfiguration(budgets(fields.get("budgets")),
                array(fields, "keyrings", 32, value -> {
                    Map<String, PkiOperationValue> item = object(value, Set.of("id", "path"), Set.of());
                    return new EnrollmentRuntimeConfiguration.Keyring(text(item, "id"), Path.of(text(item, "path")));
                }), array(fields, "credentialSets", 256, EnrollmentRuntimeConfigurationCodec::credential),
                array(fields, "activeCredentials", 256, value -> {
                    Map<String, PkiOperationValue> item = object(value, Set.of("protocol", "authorityId", "credentialId"), Set.of());
                    return new EnrollmentRuntimeConfiguration.ActiveCredential(protocol(item), text(item, "authorityId"), text(item, "credentialId"));
                }), optional(fields, "keygenArtifacts", EnrollmentRuntimeConfigurationCodec::artifacts));
    }

    private static EnrollmentRuntimeConfiguration.Budgets budgets(PkiOperationValue value) {
        Map<String, PkiOperationValue> fields = object(value, Set.of("maximumTransactions", "maximumPending",
                "maximumRetainedRequestBytes", "maximumRequestBytes", "maximumConcurrentDispatches",
                "pendingLifetimeSeconds", "retryAfterSeconds"), Set.of());
        return new EnrollmentRuntimeConfiguration.Budgets(integer(fields, "maximumTransactions"), integer(fields, "maximumPending"),
                number(fields, "maximumRetainedRequestBytes"), integer(fields, "maximumRequestBytes"),
                integer(fields, "maximumConcurrentDispatches"), seconds(fields, "pendingLifetimeSeconds"), seconds(fields, "retryAfterSeconds"));
    }

    private static EnrollmentRuntimeConfiguration.CredentialSet credential(PkiOperationValue value) {
        Map<String, PkiOperationValue> fields = object(value, Set.of("credentialId", "protocol", "authorityId", "issuerId",
                "chainPathId", "requestTrustAnchors", "authorizedRaKeys"), Set.of("signer", "pbm"));
        return new EnrollmentRuntimeConfiguration.CredentialSet(text(fields, "credentialId"), protocol(fields),
                text(fields, "authorityId"), text(fields, "issuerId"), text(fields, "chainPathId"),
                optional(fields, "signer", item -> {
                    Map<String, PkiOperationValue> signer = object(item, Set.of("key", "certificateChain"), Set.of());
                    return new EnrollmentRuntimeConfiguration.Signer(key(signer.get("key")),
                            array(signer, "certificateChain", 33, certificate -> Path.of(text(certificate))));
                }), array(fields, "requestTrustAnchors", 32, certificate -> Path.of(text(certificate))),
                array(fields, "authorizedRaKeys", 256, EnrollmentRuntimeConfigurationCodec::text),
                optional(fields, "pbm", EnrollmentRuntimeConfigurationCodec::pbm));
    }

    private static EnrollmentRuntimeConfiguration.Pbm pbm(PkiOperationValue value) {
        Map<String, PkiOperationValue> fields = object(value, Set.of("minimumIterations", "maximumIterations",
                "minimumSaltBytes", "maximumSaltBytes", "digests", "macs", "identities"), Set.of());
        List<EnrollmentRuntimeConfiguration.PbmDigest> digests = array(fields, "digests", 3,
                item -> EnrollmentRuntimeConfiguration.PbmDigest.valueOf(text(item)));
        List<EnrollmentRuntimeConfiguration.PbmMac> macs = array(fields, "macs", 3,
                item -> EnrollmentRuntimeConfiguration.PbmMac.valueOf(text(item)));
        Set<EnrollmentRuntimeConfiguration.PbmDigest> uniqueDigests = java.util.EnumSet.noneOf(EnrollmentRuntimeConfiguration.PbmDigest.class);
        uniqueDigests.addAll(digests);
        Set<EnrollmentRuntimeConfiguration.PbmMac> uniqueMacs = java.util.EnumSet.noneOf(EnrollmentRuntimeConfiguration.PbmMac.class);
        uniqueMacs.addAll(macs);
        if (uniqueDigests.size() != digests.size() || uniqueMacs.size() != macs.size()) {
            throw invalid();
        }
        return new EnrollmentRuntimeConfiguration.Pbm(integer(fields, "minimumIterations"), integer(fields, "maximumIterations"),
                integer(fields, "minimumSaltBytes"), integer(fields, "maximumSaltBytes"), Set.copyOf(digests), Set.copyOf(macs),
                array(fields, "identities", 256, item -> {
                    Map<String, PkiOperationValue> identity = object(item, Set.of("senderKid", "identityId", "secret", "ownerAliases"), Set.of());
                    return new EnrollmentRuntimeConfiguration.PbmIdentity(text(identity, "senderKid"), text(identity, "identityId"),
                            key(identity.get("secret")), array(identity, "ownerAliases", 128, EnrollmentRuntimeConfigurationCodec::text));
                }));
    }

    private static EnrollmentRuntimeConfiguration.KeygenArtifacts artifacts(PkiOperationValue value) {
        Map<String, PkiOperationValue> fields = object(value, Set.of("directory", "maximumArtifactBytes", "maximumRetainedBytes",
                "maximumArtifacts", "maximumConcurrentGenerations", "deliveryRetentionSeconds"), Set.of());
        return new EnrollmentRuntimeConfiguration.KeygenArtifacts(Path.of(text(fields, "directory")),
                number(fields, "maximumArtifactBytes"), number(fields, "maximumRetainedBytes"), integer(fields, "maximumArtifacts"),
                integer(fields, "maximumConcurrentGenerations"), seconds(fields, "deliveryRetentionSeconds"));
    }

    private static EnrollmentRuntimeConfiguration.KeyReference key(PkiOperationValue value) {
        Map<String, PkiOperationValue> fields = object(value, Set.of("keyringId", "alias"), Set.of());
        return new EnrollmentRuntimeConfiguration.KeyReference(text(fields, "keyringId"), text(fields, "alias"));
    }

    private static EnrollmentRuntimeConfiguration.Protocol protocol(Map<String, PkiOperationValue> fields) {
        return EnrollmentRuntimeConfiguration.Protocol.valueOf(text(fields, "protocol"));
    }

    private static Map<String, PkiOperationValue> object(PkiOperationValue value, Set<String> mandatory, Set<String> optional) {
        if (!(value instanceof PkiOperationValue.ObjectValue object)) {
            throw invalid();
        }
        if (!object.fields().keySet().containsAll(mandatory)) {
            throw invalid();
        }
        Set<String> permitted = new HashSet<>(mandatory);
        permitted.addAll(optional);
        if (!permitted.containsAll(object.fields().keySet())) {
            throw invalid();
        }
        return object.fields();
    }

    private static <T> List<T> array(Map<String, PkiOperationValue> fields, String key, int maximum,
            Function<PkiOperationValue, T> converter) {
        if (!(fields.get(key) instanceof PkiOperationValue.ListValue array) || array.values().size() > maximum) {
            throw invalid();
        }
        return array.values().stream().map(converter).toList();
    }

    private static <T> Optional<T> optional(Map<String, PkiOperationValue> fields, String key,
            Function<PkiOperationValue, T> converter) {
        return fields.containsKey(key) ? Optional.of(converter.apply(fields.get(key))) : Optional.empty();
    }

    private static String text(Map<String, PkiOperationValue> fields, String key) { return text(fields.get(key)); }
    private static String text(PkiOperationValue value) {
        if (!(value instanceof PkiOperationValue.Text text) || text.value().length() > 4096) {
            throw invalid();
        }
        return text.value();
    }
    private static long number(Map<String, PkiOperationValue> fields, String key) {
        if (!(fields.get(key) instanceof PkiOperationValue.IntegerValue number)) {
            throw invalid();
        }
        return number.value();
    }
    private static int integer(Map<String, PkiOperationValue> fields, String key) {
        long value = number(fields, key);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) {
            throw invalid();
        }
        return (int) value;
    }
    private static Duration seconds(Map<String, PkiOperationValue> fields, String key) { return Duration.ofSeconds(number(fields, key)); }
    private static IllegalArgumentException invalid() { return new IllegalArgumentException("Invalid enrollment runtime configuration document"); }
}
