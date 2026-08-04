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
package zeroecho.pki.impl.framework.x509;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonFactoryBuilder;
import zeroecho.core.alg.BootstrapAlgorithmIdentities;
import zeroecho.core.spec.AlgorithmIdentity;
import zeroecho.pki.api.algorithm.X509AlgorithmBinding;

/** Loads and locks the version-one ZeroEcho-owned private X.509 assignments. */
public final class ZeroEchoPrivateX509Bindings {

    /** Versioned assignment resource. */
    public static final String RESOURCE = "/zeroecho/pki/x509/zeroecho-private-bindings-v1.json";
    private static final int MAXIMUM_RESOURCE_BYTES = 64 * 1024;
    private static final Set<String> ROOT_FIELDS = Set.of("schemaVersion", "bindings");
    private static final Set<String> BINDING_FIELDS = Set.of("bindingId", "algorithmIdentity", "role", "oid",
            "encodingVersion", "parameterRule", "publicKeyEncoding", "signatureEncoding", "interoperability");
    private static final JsonFactory JSON = new JsonFactoryBuilder()
            .streamReadConstraints(StreamReadConstraints.builder().maxDocumentLength(MAXIMUM_RESOURCE_BYTES)
                    .maxNestingDepth(8).maxStringLength(512).build())
            .build();
    private static final AssignmentSet ASSIGNMENTS = loadResource();

    private ZeroEchoPrivateX509Bindings() {
    }

    /** @return frozen safe descriptors in resource order */
    public static List<X509AlgorithmBinding> descriptors() {
        return ASSIGNMENTS.descriptors();
    }

    /** @return trusted immutable encoding-rule catalog */
    public static X509BindingCatalog catalog() {
        return ASSIGNMENTS.catalog();
    }

    @SuppressWarnings({ "PMD.AvoidCatchingGenericException", "PMD.ExceptionAsFlowControl",
            "PMD.AvoidLiteralsInIfCondition" })
    private static AssignmentSet loadResource() {
        try (InputStream input = ZeroEchoPrivateX509Bindings.class.getResourceAsStream(RESOURCE)) {
            if (input == null) {
                throw new IllegalStateException("ZeroEcho X.509 assignment resource is missing");
            }
            try (JsonParser parser = JSON.createParser(ObjectReadContext.empty(), input)) {
                require(parser.nextToken(), JsonToken.START_OBJECT);
                Set<String> seen = new HashSet<>();
                int schema = 0;
                List<X509AlgorithmBinding> bindings = null;
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    String field = parser.currentName();
                    if (!ROOT_FIELDS.contains(field) || !seen.add(field)) {
                        throw invalid();
                    }
                    parser.nextToken();
                    if ("schemaVersion".equals(field)) {
                        schema = parser.getIntValue();
                    } else {
                        bindings = readBindings(parser);
                    }
                }
                if (parser.nextToken() != null || schema != 1 || bindings == null || seen.size() != ROOT_FIELDS.size()) {
                    throw invalid();
                }
                return validate(bindings);
            }
        } catch (IOException | RuntimeException failure) {
            throw new IllegalStateException("ZeroEcho X.509 assignment resource is invalid", failure);
        }
    }

    @SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.AvoidInstantiatingObjectsInLoops",
            "PMD.AvoidLiteralsInIfCondition" })
    private static List<X509AlgorithmBinding> readBindings(JsonParser parser) throws IOException {
        require(parser.currentToken(), JsonToken.START_ARRAY);
        List<X509AlgorithmBinding> bindings = new ArrayList<>();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            require(parser.currentToken(), JsonToken.START_OBJECT);
            Set<String> seen = new HashSet<>();
            String id = null;
            String identity = null;
            String role = null;
            String oid = null;
            int version = 0;
            String parameters = null;
            String publicKey = null;
            String signature = null;
            String interoperability = null;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String field = parser.currentName();
                if (!BINDING_FIELDS.contains(field) || !seen.add(field)) {
                    throw invalid();
                }
                parser.nextToken();
                if ("encodingVersion".equals(field)) {
                    version = parser.getIntValue();
                } else {
                    String value = parser.getValueAsString();
                    switch (field) {
                        case "bindingId" -> id = value;
                        case "algorithmIdentity" -> identity = value;
                        case "role" -> role = value;
                        case "oid" -> oid = value;
                        case "parameterRule" -> parameters = value;
                        case "publicKeyEncoding" -> publicKey = value;
                        case "signatureEncoding" -> signature = value;
                        case "interoperability" -> interoperability = value;
                        default -> throw invalid();
                    }
                }
            }
            if (seen.size() != BINDING_FIELDS.size()) {
                throw invalid();
            }
            AlgorithmIdentity exactIdentity = identity(identity);
            String commitment = String.join("|", id, exactIdentity.canonicalForm(), role, oid,
                    Integer.toString(version), parameters, publicKey, signature, interoperability);
            bindings.add(new X509AlgorithmBinding(id, exactIdentity, X509AlgorithmBinding.Role.valueOf(role), oid,
                    X509AlgorithmBinding.Origin.ZEROECHO_PRIVATE, version,
                    X509AlgorithmBinding.ParameterRule.valueOf(parameters),
                    X509AlgorithmBinding.PublicKeyEncoding.valueOf(publicKey),
                    X509AlgorithmBinding.SignatureEncoding.valueOf(signature),
                    X509AlgorithmBinding.Interoperability.valueOf(interoperability), Optional.empty(), commitment));
        }
        return List.copyOf(bindings);
    }

    @SuppressWarnings("PMD.AvoidLiteralsInIfCondition")
    private static AssignmentSet validate(List<X509AlgorithmBinding> descriptors) {
        if (descriptors.size() != 4) {
            throw invalid();
        }
        ImmutableX509AlgorithmBindingRegistry.create(descriptors);
        List<X509BindingRule> rules = descriptors.stream().map(PrivateRule::new).map(X509BindingRule.class::cast)
                .toList();
        return new AssignmentSet(descriptors, X509BindingCatalog.builtIn(rules));
    }

    private static AlgorithmIdentity identity(String value) {
        return switch (Objects.requireNonNull(value, "algorithmIdentity")) {
            case "SPHINCS_PLUS_SIGNATURE" -> BootstrapAlgorithmIdentities.SPHINCS_PLUS_SIGNATURE;
            case "SPHINCS_PLUS_PUBLIC_KEY" -> BootstrapAlgorithmIdentities.SPHINCS_PLUS_PUBLIC_KEY;
            default -> throw invalid();
        };
    }

    private static void require(JsonToken actual, JsonToken expected) {
        if (actual != expected) {
            throw invalid();
        }
    }

    private static IllegalArgumentException invalid() {
        return new IllegalArgumentException("Invalid ZeroEcho X.509 assignment schema");
    }

    private record AssignmentSet(List<X509AlgorithmBinding> descriptors, X509BindingCatalog catalog) {
        private AssignmentSet {
            descriptors = List.copyOf(descriptors);
            Objects.requireNonNull(catalog, "catalog");
        }
    }

    private record PrivateRule(X509AlgorithmBinding binding) implements X509BindingRule {
        private PrivateRule {
            Objects.requireNonNull(binding, "binding");
        }

        @Override
        public String id() {
            return binding.bindingId();
        }

        @Override
        public X509AlgorithmRole role() {
            return binding.role() == X509AlgorithmBinding.Role.SUBJECT_PUBLIC_KEY
                    ? X509AlgorithmRole.SUBJECT_PUBLIC_KEY_ALGORITHM : X509AlgorithmRole.SIGNATURE_ALGORITHM;
        }

        @Override
        public String oid() {
            return binding.oid();
        }

        @Override
        public String semanticFingerprint() {
            return binding.semanticCommitment();
        }

        @Override
        public SignatureEncoding signatureEncoding() {
            return switch (binding.signatureEncoding()) {
                case OPAQUE -> SignatureEncoding.OPAQUE;
                case ECDSA_DER -> SignatureEncoding.ECDSA_DER;
                case NOT_APPLICABLE -> SignatureEncoding.NOT_APPLICABLE;
            };
        }

        @Override
        public PublicKeyEncoding publicKeyEncoding() {
            return switch (binding.publicKeyEncoding()) {
                case NESTED_SPKI_DER -> PublicKeyEncoding.NESTED_SPKI_DER;
                case RAW -> PublicKeyEncoding.RAW;
                case RSA_PKCS1_DER -> PublicKeyEncoding.RSA_PKCS1_DER;
                case EC_POINT -> PublicKeyEncoding.EC_POINT;
                case NOT_APPLICABLE -> PublicKeyEncoding.NOT_APPLICABLE;
            };
        }

        @Override
        public List<X509AlgorithmBinding> bindings() {
            return List.of(binding);
        }

        @Override
        public Optional<X509AlgorithmIdentifier> encode(AlgorithmIdentity identity) {
            return binding.algorithmIdentity().equals(identity)
                    ? Optional.of(X509AlgorithmIdentifier.absent(binding.oid())) : Optional.empty();
        }

        @Override
        public Optional<AlgorithmIdentity> decode(X509AlgorithmIdentifier identifier) {
            if (!binding.oid().equals(identifier.oid())) {
                return Optional.empty();
            }
            if (identifier.parameterForm() != X509AlgorithmIdentifier.ParameterForm.ABSENT) {
                throw new IllegalArgumentException("Private X.509 binding parameters must be absent");
            }
            return Optional.of(binding.algorithmIdentity());
        }
    }
}
