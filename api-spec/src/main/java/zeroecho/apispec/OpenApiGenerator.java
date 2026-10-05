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
package zeroecho.apispec;

import java.io.IOException;
import zeroecho.pki.server.schema.OperationDescriptorCatalog;
import zeroecho.pki.server.schema.OperationParameterSchema.FieldSpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Build-time OpenAPI 3.1 specification generator for the ZeroEcho PKI administrative API.
 *
 * <p>This program projects the validated {@link OperationDescriptorCatalog}
 * into an OpenAPI 3.1 YAML document, including unavailable operations with an
 * explicit availability annotation.</p>
 *
 * <p>Human-readable descriptions for each operation and field are taken from an
 * {@code openapi-supplement.yaml} file. The generator validates that every operation
 * present in the registry has a supplement entry and lists missing entries on standard
 * error before exiting with code 1.</p>
 *
 * <p>Usage: {@code OpenApiGenerator <version> <supplement.yaml> <output.yaml>}</p>
 *
 * <h2>Supplement YAML format</h2>
 * <pre>
 * operations:
 *   ca.create:
 *     summary: "Creates a root CA authority"
 *     description: "..."
 *     arguments:
 *       formatId:
 *         description: "Encoding format identifier"
 * </pre>
 *
 * @since 1.0
 */
public final class OpenApiGenerator {
    private static final int ARGUMENT_COUNT = 3;
    private static final Map<String, String> TAG_MAP = new LinkedHashMap<>();
    private static final String TEXT_DESCRIPTION = "description";
    private static final String TEXT_TYPE = "type";
    private static final String TEXT_REQUIRED = "required";
    private static final String TEXT__REF = "$ref";
    private static final String TEXT_PROPERTIES = "properties";
    private static final String TEXT_OBJECT = "object";
    private static final String TEXT_STRING = "string";


    /** Creates a build-time generator without loading the catalog or writing output. */
    public OpenApiGenerator() {
        // The generator has no per-instance state.
    }

    /**
     * Program entry point.
     *
     * @param args {@code [version, supplement-yaml-path, output-yaml-path]}
     * @throws IOException if supplement validation or output writing fails
     */
    public static void main(String[] args) throws IOException {
        if (args.length != ARGUMENT_COUNT) {
            System.err.println("Usage: OpenApiGenerator <version> <supplement.yaml> <output.yaml>");
            System.exit(1);
        }
        String version = args[0];
        Path supplementPath = Path.of(args[1]);
        Path outputPath = Path.of(args[2]);

        OpenApiGenerator generator = new OpenApiGenerator();
        generator.generate(version, supplementPath, outputPath);
    }

    private void generate(String version, Path supplementPath, Path outputPath) throws IOException {
        // 1. Load operation IDs and descriptors from the registry.
        Map<String, OperationDescriptorCatalog.Entry> descriptors = loadDescriptors();

        // 3. Parse supplement YAML.
        Map<String, Object> supplement = parseSupplementYaml(supplementPath);

        // 4. Validate supplement completeness.
        validateSupplement(descriptors, supplement);

        // 5. Generate OpenAPI YAML.
        String yaml = generateYaml(version, descriptors, supplement);

        // 6. Write output.
        Files.writeString(outputPath, yaml, StandardCharsets.UTF_8);
        System.out.println("Generated OpenAPI spec: " + outputPath);
    }

    // -- Step 1: Load descriptors

    private Map<String, OperationDescriptorCatalog.Entry> loadDescriptors() {
        Map<String, OperationDescriptorCatalog.Entry> result = new LinkedHashMap<>();
        for (OperationDescriptorCatalog.Entry entry : OperationDescriptorCatalog.current().entries()) {
            result.put(entry.security().operationId(), entry);
        }
        return result;
    }

    // -- Step 3: Parse supplement YAML (minimal parser)

    /**
     * Parses the supplement YAML file into a nested {@code Map<String, Object>}.
     *
     * <p>Only handles the subset of YAML used by the supplement file: indented block
     * mappings with string values. No sequences, no anchors, no multi-line scalars.</p>
     *
     * @param path supplement YAML path
     * @return nested map representation
     * @throws IOException if the file cannot be read
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> parseSupplementYaml(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        Map<String, Object> root = new LinkedHashMap<>();
        // Stack of (indentLevel, map) pairs
        List<int[]> indentStack = new ArrayList<>();
        List<Map<String, Object>> mapStack = new ArrayList<>();
        indentStack.add(new int[]{-1});
        mapStack.add(root);

        for (String rawLine : lines) {
            if (rawLine.isBlank() || rawLine.stripLeading().startsWith("#")) {
                continue;
            }
            int indent = countLeadingSpaces(rawLine);
            String trimmed = rawLine.stripLeading();

            // Pop stack until we find the right parent indent
            while (mapStack.size() > 1 && indentStack.get(indentStack.size() - 1)[0] >= indent) {
                indentStack.remove(indentStack.size() - 1);
                mapStack.remove(mapStack.size() - 1);
            }

            int colonIdx = trimmed.indexOf(':');
            if (colonIdx < 0) {
                continue; // skip malformed lines
            }
            String key = trimmed.substring(0, colonIdx).trim();
            String rest = trimmed.substring(colonIdx + 1).trim();

            Map<String, Object> current = mapStack.get(mapStack.size() - 1);

            if (rest.isEmpty()) {
                // Block mapping: next lines are children
                Map<String, Object> child = new LinkedHashMap<>(); // NOPMD AvoidInstantiatingObjectsInLoops - Each parsed block owns an independent child mapping.
                current.put(key, child);
                indentStack.add(new int[]{indent});
                mapStack.add(child);
            } else {
                // Scalar value — strip quotes if present
                String value = rest;
                if ((value.startsWith("\"") && value.endsWith("\""))
                        || (value.startsWith("'") && value.endsWith("'"))) {
                    value = value.substring(1, value.length() - 1);
                }
                current.put(key, value);
            }
        }
        return root;
    }

    private static int countLeadingSpaces(String line) {
        int count = 0;
        while (count < line.length() && line.charAt(count) == ' ') {
            count++;
        }
        return count;
    }

    // -- Step 4: Validate supplement completeness

    @SuppressWarnings("unchecked")
    private void validateSupplement(Map<String, OperationDescriptorCatalog.Entry> descriptors, Map<String, Object> supplement)
            throws IOException {
        Object ops = supplement.get("operations");
        if (!(ops instanceof Map)) {
            throw new IOException("supplement.yaml is missing the top-level 'operations' key");
        }
        Map<String, Object> opMap = (Map<String, Object>) ops;
        List<String> missing = new ArrayList<>();
        for (String opId : descriptors.keySet()) {
            if (!opMap.containsKey(opId)) {
                missing.add(opId);
            }
        }
        if (!missing.isEmpty()) {
            System.err.println("ERROR: supplement.yaml is missing entries for " + missing.size()
                    + " operation(s):");
            missing.stream().sorted().forEach(id -> System.err.println("  - " + id));
            System.err.println("Add these operations to the 'operations' section of openapi-supplement.yaml.");
            throw new IOException("supplement.yaml is missing operation entries");
        }
    }

    // -- Step 5: Generate YAML

    @SuppressWarnings("unchecked")
    private String generateYaml(String version, Map<String, OperationDescriptorCatalog.Entry> descriptors,
            Map<String, Object> supplement) {
        YamlBuilder y = new YamlBuilder();
        Map<String, Object> ops = (Map<String, Object>) supplement.get("operations");

        // Header
        y.rawLine("openapi: \"3.1.0\"");
        y.blank();

        // Info
        y.blockMapping("info", () -> {
            y.mapping("title", "ZeroEcho PKI Administrative API");
            y.mapping("version", version);
            y.mapping(TEXT_DESCRIPTION,
                    "Mutual-TLS administrative API for ZeroEcho PKI. All endpoints require a "
                    + "client certificate. Every operation is dispatched as POST /operations/{operationId}.");
            y.blockMapping("license", () -> {
                y.mapping("name", "BSD 4-Clause");
                y.mapping("identifier", "BSD-4-Clause");
            });
        });
        y.blank();

        // Servers
        y.blockMapping("servers", () -> {
            y.sequenceItem(() -> {
                y.mapping("url", "https://{host}:{port}/admin/v1");
                y.mapping(TEXT_DESCRIPTION, "ZeroEcho PKI administrative listener");
                y.blockMapping("variables", () -> {
                    y.blockMapping("host", () -> {
                        y.mapping("default", "localhost");
                        y.mapping(TEXT_DESCRIPTION, "Server hostname or IP address");
                    });
                    y.blockMapping("port", () -> {
                        y.mapping("default", "8443");
                        y.mapping(TEXT_DESCRIPTION, "Administrative HTTPS listener port");
                    });
                });
            });
        });
        y.blank();

        // Security
        y.blockMapping("security", () -> {
            y.sequenceItem(() -> y.mappingLiteral("mutualTLS", "[]"));
        });
        y.blank();

        // Tags
        y.blockMapping("tags", () -> {
            for (Map.Entry<String, String> tag : TAG_MAP.entrySet()) {
                y.sequenceItem(() -> {
                    y.mapping("name", tag.getValue());
                    y.mapping(TEXT_DESCRIPTION, "Operations in the " + tag.getValue() + " domain");
                });
            }
        });
        y.blank();

        // Paths
        y.blockMapping("paths", () -> {
            // Discovery endpoint
            y.blockMapping("/operations", () -> {
                y.blockMapping("get", () -> {
                    y.mapping("operationId", "operations.list");
                    y.mapping("summary", "List available operations");
                    y.mapping(TEXT_DESCRIPTION,
                            "Returns the set of operation identifiers available to the authenticated principal.");
                    emitStandardResponses(y);
                });
            });
            y.blank();

            // Per-operation endpoints
            for (Map.Entry<String, OperationDescriptorCatalog.Entry> entry : descriptors.entrySet()) {
                String opId = entry.getKey();
                OperationDescriptorCatalog.Entry descriptor = entry.getValue();
                Map<String, Object> opSupplement = ops.containsKey(opId) ?
                        (Map<String, Object>) ops.get(opId) : Map.of();
                boolean highRisk = isHighRisk(descriptor);
                String tag = deriveTag(opId);

                y.blockMapping("'/operations/" + opId + "'", () -> {
                    y.blockMapping("post", () -> {
                        y.mapping("operationId", opId);
                        y.mappingLiteral("x-zeroecho-available", Boolean.toString(descriptor.available()));
                        y.mapping("x-zeroecho-permission-action", descriptor.security().action().name());
                        y.mapping("x-zeroecho-resource-type", descriptor.security().resourceType().name());
                        y.mapping("x-zeroecho-scope", descriptor.presentation().transport().scope());
                        y.mapping("x-zeroecho-authority-from", descriptor.presentation().transport().authorityFrom());
                        String summary = getStringOrDefault(opSupplement, "summary", "TODO: " + opId);
                        y.mapping("summary", summary);
                        String description = getStringOrDefault(opSupplement, TEXT_DESCRIPTION, "");
                        if (!description.isEmpty()) {
                            y.mapping(TEXT_DESCRIPTION, description);
                        }
                        y.blockMapping("tags", () -> y.sequenceItemString(tag));
                        emitRequestBody(y, opId);
                        emitResponses(y, highRisk);
                    });
                });
                y.blank();
            }

            // Cancellation endpoint
            y.blockMapping("'/operations/{operationId}/{requestId}'", () -> {
                y.blockMapping("delete", () -> {
                    y.mapping("operationId", "operations.cancel");
                    y.mapping("summary", "Cancel an in-flight operation");
                    emitStandardResponses(y);
                });
            });
        });
        y.blank();

        // Components
        y.blockMapping("components", () -> {
            // Security schemes
            y.blockMapping("securitySchemes", () -> {
                y.blockMapping("mutualTLS", () -> {
                    y.mappingLiteral(TEXT_TYPE, "mutualTLS");
                    y.mapping(TEXT_DESCRIPTION,
                            "Every request must present a valid client certificate issued by the "
                            + "server's configured client trust anchors. No sessions or tokens exist.");
                });
            });
            y.blank();

            // Common schemas
            y.blockMapping("schemas", () -> {
                emitCommonSchemas(y);
                y.blank();

                // Per-operation argument schemas
                for (Map.Entry<String, OperationDescriptorCatalog.Entry> entry : descriptors.entrySet()) {
                    String opId = entry.getKey();
                    {
                        Map<String, Object> opSupplement = ops.containsKey(opId) ?
                                (Map<String, Object>) ops.get(opId) : Map.of();
                        emitArgumentSchema(y, opId, entry.getValue(), opSupplement);
                    }
                }
            });

            // Standard responses
            y.blank();
            y.blockMapping("responses", () -> {
                emitStandardResponseComponents(y);
            });
        });

        return y.build();
    }

    static {
        TAG_MAP.put("ca",            "Authorities");
        TAG_MAP.put("credential",    "Credentials");
        TAG_MAP.put("issuer",        "Issuers");
        TAG_MAP.put("profile",       "Profiles");
        TAG_MAP.put("request",       "Requests");
        TAG_MAP.put("revocation",    "Revocation");
        TAG_MAP.put("status",        "Status Objects");
        TAG_MAP.put("publication",   "Publication");
        TAG_MAP.put("algorithm",     "Algorithm Bindings");
        TAG_MAP.put("configuration", "Configuration");
        TAG_MAP.put("inventory",     "Inventory");
        TAG_MAP.put("security",      "Principals and Roles");
        TAG_MAP.put("role",          "Roles");
        TAG_MAP.put("grant",         "Grants");
        TAG_MAP.put("approval",      "Approvals");
        TAG_MAP.put("break-glass",   "Break Glass");
        TAG_MAP.put("audit",         "Audit");
        TAG_MAP.put("capability",    "Capabilities");
        TAG_MAP.put("repository",    "Repository Aliases");
        TAG_MAP.put("acme",          "ACME");
        TAG_MAP.put("ocsp",          "OCSP");
        TAG_MAP.put("server",        "Server");
    }

    private String deriveTag(String opId) {
        String prefix = opId.contains(".") ? opId.substring(0, opId.indexOf('.')) : opId;
        return TAG_MAP.getOrDefault(prefix, prefix);
    }

    private boolean isHighRisk(OperationDescriptorCatalog.Entry descriptor) {
        return descriptor.security().approvalCategory() == zeroecho.pki.server.OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK;
    }

    private void emitRequestBody(YamlBuilder y, String opId) {
        String schemaName = toSchemaName(opId) + "Arguments";
        y.blockMapping("requestBody", () -> {
            y.mappingLiteral(TEXT_REQUIRED, "true");
            y.blockMapping("content", () -> {
                y.blockMapping("application/json", () -> {
                    y.blockMapping("schema", () -> {
                        y.blockMapping("allOf", () -> {
                            y.sequenceItem(() -> y.mapping(TEXT__REF, "#/components/schemas/OperationRequest"));
                            {
                                y.sequenceItem(() -> {
                                    y.blockMapping(TEXT_PROPERTIES, () -> {
                                        y.blockMapping("arguments", () -> {
                                            y.mapping(TEXT__REF,
                                                    "#/components/schemas/" + schemaName);
                                        });
                                    });
                                });
                            }
                        });
                    });
                });
            });
        });
    }

    private void emitResponses(YamlBuilder y, boolean highRisk) {
        y.blockMapping("responses", () -> {
            y.blockMapping("'200'", () -> {
                y.mapping(TEXT_DESCRIPTION, "Operation completed successfully");
                y.blockMapping("content", () -> {
                    y.blockMapping("application/json", () -> {
                        y.refMapping("schema", "#/components/schemas/OperationResponse");
                    });
                });
            });
            if (highRisk) {
                y.blockMapping("'409'", () -> {
                    y.mapping(TEXT_DESCRIPTION, "Dual-control approval required before the operation can proceed");
                    y.blockMapping("content", () -> {
                        y.blockMapping("application/json", () -> {
                            y.refMapping("schema", "#/components/schemas/ApprovalResponse");
                        });
                    });
                });
            }
            y.blockMapping("'400'", () -> y.mapping(TEXT__REF, "#/components/responses/BadRequest"));
            y.blockMapping("'401'", () -> y.mapping(TEXT__REF, "#/components/responses/Unauthorized"));
            y.blockMapping("'403'", () -> y.mapping(TEXT__REF, "#/components/responses/Forbidden"));
            y.blockMapping("'404'", () -> y.mapping(TEXT__REF, "#/components/responses/NotFound"));
            y.blockMapping("'500'", () -> y.mapping(TEXT__REF, "#/components/responses/InternalError"));
        });
    }

    private void emitStandardResponses(YamlBuilder y) {
        y.blockMapping("responses", () -> {
            y.blockMapping("'200'", () -> {
                y.mapping(TEXT_DESCRIPTION, "Success");
                y.blockMapping("content", () -> {
                    y.blockMapping("application/json", () -> {
                        y.refMapping("schema", "#/components/schemas/OperationResponse");
                    });
                });
            });
        });
    }

    private void emitCommonSchemas(YamlBuilder y) {
        // OperationRequest
        y.blockMapping("OperationRequest", () -> {
            y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
            y.mappingLiteral("additionalProperties", "false");
            y.blockMapping(TEXT_REQUIRED, () -> {
                y.sequenceItemString("version");
            });
            y.blockMapping(TEXT_PROPERTIES, () -> {
                y.blockMapping("version", () -> {
                    y.mappingLiteral(TEXT_TYPE, "integer");
                    y.mapping(TEXT_DESCRIPTION, "Envelope version; must be 1");
                });
                y.blockMapping("authorityId", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    y.mapping(TEXT_DESCRIPTION,
                            "Required for authority-scoped operations; must be omitted for realm-wide operations");
                });
                y.blockMapping("approvalId", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    y.mapping(TEXT_DESCRIPTION,
                            "Supplied when re-submitting an operation that requires dual control approval");
                });
                y.blockMapping("deadline", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    y.mapping("format", "duration");
                    y.mapping(TEXT_DESCRIPTION,
                            "ISO-8601 duration bounding server-side execution time, e.g. PT30S");
                });
                y.blockMapping("arguments", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
                    y.mapping(TEXT_DESCRIPTION, "Operation-specific arguments; schema depends on operationId");
                });
            });
        });
        y.blank();

        // OperationResponse
        y.blockMapping("OperationResponse", () -> {
            y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
            y.blockMapping(TEXT_REQUIRED, () -> {
                y.sequenceItemString("version");
                y.sequenceItemString("requestId");
                y.sequenceItemString("operation");
                y.sequenceItemString("status");
            });
            y.blockMapping(TEXT_PROPERTIES, () -> {
                y.blockMapping("version", () -> y.mappingLiteral(TEXT_TYPE, "integer"));
                y.blockMapping("requestId", () -> y.mappingLiteral(TEXT_TYPE, TEXT_STRING));
                y.blockMapping("operation", () -> y.mappingLiteral(TEXT_TYPE, TEXT_STRING));
                y.blockMapping("status", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    y.blockMapping("enum", () -> {
                        y.sequenceItemString("SUCCEEDED");
                        y.sequenceItemString("PENDING");
                        y.sequenceItemString("FAILED");
                        y.sequenceItemString("APPROVAL_REQUIRED");
                    });
                });
                y.blockMapping("result", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
                    y.mappingLiteral("nullable", "true");
                    y.mapping(TEXT_DESCRIPTION, "Operation-specific result; null on FAILED");
                });
                y.blockMapping("failure", () -> {
                    y.mappingLiteral("nullable", "true");
                    y.mapping(TEXT__REF, "#/components/schemas/OperationFailure");
                });
            });
        });
        y.blank();

        // OperationFailure
        y.blockMapping("OperationFailure", () -> {
            y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
            y.blockMapping(TEXT_REQUIRED, () -> {
                y.sequenceItemString("code");
                y.sequenceItemString("message");
            });
            y.blockMapping(TEXT_PROPERTIES, () -> {
                y.blockMapping("code", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    y.mapping(TEXT_DESCRIPTION, "Machine-readable failure code");
                });
                y.blockMapping("message", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    y.mapping(TEXT_DESCRIPTION, "Human-readable failure description");
                });
                y.blockMapping("details", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
                    y.blockMapping("additionalProperties", () -> y.mappingLiteral(TEXT_TYPE, TEXT_STRING));
                });
            });
        });
        y.blank();

        // ApprovalCommitment
        y.blockMapping("ApprovalCommitment", () -> {
            y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
            y.blockMapping(TEXT_REQUIRED, () -> {
                y.sequenceItemString("operationCommitment");
                y.sequenceItemString("approvalTarget");
            });
            y.blockMapping(TEXT_PROPERTIES, () -> {
                y.blockMapping("operationCommitment", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    y.mapping(TEXT_DESCRIPTION,
                            "SHA-256 commitment identifying this operation instance for approval re-submission");
                });
                y.blockMapping("approvalTarget", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    y.mapping(TEXT_DESCRIPTION, "The operationId the approval workflow is attached to");
                });
            });
        });
        y.blank();

        // ApprovalResponse (for 409 on HIGH_RISK ops)
        y.blockMapping("ApprovalResponse", () -> {
            y.blockMapping("allOf", () -> {
                y.sequenceItem(() -> y.mapping(TEXT__REF, "#/components/schemas/OperationResponse"));
                y.sequenceItem(() -> {
                    y.blockMapping(TEXT_PROPERTIES, () -> {
                        y.blockMapping("status", () -> {
                            y.blockMapping("enum", () -> y.sequenceItemString("APPROVAL_REQUIRED"));
                        });
                        y.blockMapping("result", () -> {
                            y.mapping(TEXT__REF, "#/components/schemas/ApprovalCommitment");
                        });
                    });
                });
            });
        });
    }

    @SuppressWarnings("unchecked")
    private void emitArgumentSchema(YamlBuilder y, String opId, OperationDescriptorCatalog.Entry descriptor,
            Map<String, Object> opSupplement) {
        Map<String, Object> descriptions = opSupplement.get("arguments") instanceof Map<?, ?> map
                ? (Map<String, Object>) map : Map.of();
        y.blockMapping(toSchemaName(opId) + "Arguments", () -> {
            y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
            y.mappingLiteral("additionalProperties", "false");
            List<String> required = descriptor.parameters().fields().stream().filter(FieldSpec::required).map(FieldSpec::name).toList();
            if (!required.isEmpty()) { y.blockMapping(TEXT_REQUIRED, () -> required.forEach(y::sequenceItemString)); }
            if (descriptor.parameters().fields().isEmpty()) { y.mappingLiteral(TEXT_PROPERTIES, "{}"); }
            else { y.blockMapping(TEXT_PROPERTIES, () -> {
                for (FieldSpec field : descriptor.parameters().fields()) {
                    y.blockMapping(field.name(), () -> {
                        emitFieldSchema(y, field);
                        if (descriptions.containsKey(field.name())) { y.mapping(TEXT_DESCRIPTION, descriptions.get(field.name()).toString()); }
                    });
                }
            }); }
        });
        y.blank();
    }

    private void emitFieldSchema(YamlBuilder y, FieldSpec field) {
        switch (field.type()) {
            case TEXT, ENUM, BASE64 -> {
                y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                if (field.type() == zeroecho.pki.server.schema.OperationParameterSchema.FieldType.BASE64) { y.mapping("format", "byte"); }
                if (!field.choices().isEmpty()) { y.blockMapping("enum", () -> field.choices().forEach(y::sequenceItemString)); }
            }
            case INTEGER -> y.mappingLiteral(TEXT_TYPE, "integer");
            case BOOLEAN -> y.mappingLiteral(TEXT_TYPE, "boolean");
            case OBJECT -> y.mappingLiteral(TEXT_TYPE, TEXT_OBJECT);
            case TEXT_SET, ENUM_SET -> {
                y.mappingLiteral(TEXT_TYPE, "array");
                y.mappingLiteral("uniqueItems", "true");
                y.blockMapping("items", () -> {
                    y.mappingLiteral(TEXT_TYPE, TEXT_STRING);
                    if (!field.choices().isEmpty()) { y.blockMapping("enum", () -> field.choices().forEach(y::sequenceItemString)); }
                });
            }
        }
    }

    private void emitStandardResponseComponents(YamlBuilder y) {
        Map<String, String> responses = new LinkedHashMap<>();
        responses.put("BadRequest",     "Malformed request body or unknown fields");
        responses.put("Unauthorized",   "No valid client certificate was presented");
        responses.put("Forbidden",      "Authenticated but not authorized for this operation");
        responses.put("NotFound",       "Referenced object does not exist");
        responses.put("InternalError",  "Server-side error during operation processing");
        for (Map.Entry<String, String> resp : responses.entrySet()) {
            y.blockMapping(resp.getKey(), () -> {
                y.mapping(TEXT_DESCRIPTION, resp.getValue());
                y.blockMapping("content", () -> {
                    y.blockMapping("application/json", () -> {
                        y.refMapping("schema", "#/components/schemas/OperationResponse");
                    });
                });
            });
        }
    }

    /**
     * Converts a dot-separated operation ID to a PascalCase schema name.
     *
     * <p>Example: {@code credential.issue} → {@code CredentialIssue}</p>
     *
     * @param opId dot-separated operation identifier
     * @return PascalCase schema name derived from the operation ID
     */
    /* default */ static String toSchemaName(String opId) {
        StringBuilder sb = new StringBuilder();
        for (String part : opId.split("[.\\-]")) {
            if (!part.isEmpty()) {
                sb.append(Character.toUpperCase(part.charAt(0))).append(part.substring(1));
            }
        }
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private String getStringOrDefault(Map<String, Object> map, String key, String defaultValue) {
        Object value = map.get(key);
        return value instanceof String s ? s : defaultValue;
    }
}
