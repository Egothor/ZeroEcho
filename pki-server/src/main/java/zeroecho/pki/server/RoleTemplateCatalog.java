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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import tools.jackson.core.JsonParser;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.JsonToken;
import tools.jackson.core.TokenStreamFactory;
import tools.jackson.core.json.JsonFactory;

/** Strict deterministic loader for versioned built-in role templates. */
@SuppressWarnings({ "PMD.CyclomaticComplexity", "PMD.ControlStatementBraces",
        "PMD.FieldDeclarationsShouldBeAtStartOfClass", "PMD.ExceptionAsFlowControl",
        "PMD.AvoidCatchingGenericException", "PMD.PreserveStackTrace", "PMD.UseEnumCollections" })
public final class RoleTemplateCatalog {
    /** Classpath resource holding the normative role templates. */
    public static final String RESOURCE = "zeroecho/pki/server/security/role-templates-v1.json";
    private static final int MAXIMUM_RESOURCE_BYTES = 131_072;
    private static final TokenStreamFactory JSON = JsonFactory.builder().build();

    /**
     * Immutable role template that has no authority until scoped assignment.
     *
     * @param templateId stable template identifier
     * @param version positive template version
     * @param actions finite permission actions supplied by the template
     */
    public record Template(String templateId, int version, Set<Permission.Action> actions) {
        /** Validates the stable template. */
        public Template {
            Permission.requireId(templateId, "role template");
            if (version <= 0) throw new IllegalArgumentException("Role template version must be positive");
            actions = Set.copyOf(Objects.requireNonNull(actions, "actions"));
            if (actions.isEmpty()) throw new IllegalArgumentException("Role template actions must not be empty");
        }
    }

    /**
     * Persistable scoped role assignment; the template itself grants nothing.
     *
     * @param assignmentId stable assignment identifier
     * @param principalId grantee principal
     * @param templateId exact template identifier
     * @param templateVersion exact template version
     * @param scope non-wildcard realm and optional subscopes
     * @param expiresAt optional mandatory assignment expiry
     * @param enabled whether the assignment participates in authorization
     */
    public record Assignment(String assignmentId, String principalId, String templateId,
            int templateVersion, Permission.Scope scope, java.util.Optional<java.time.Instant> expiresAt,
            boolean enabled) {
        /** Validates the exact scoped assignment. */
        public Assignment {
            Permission.requireId(assignmentId, "assignment");
            Permission.requirePrincipal(principalId);
            Permission.requireId(templateId, "role template");
            if (templateVersion <= 0) throw new IllegalArgumentException("Template version must be positive");
            Objects.requireNonNull(scope, "scope");
            expiresAt = Objects.requireNonNull(expiresAt, "expiresAt");
        }

        /**
         * Creates an assignment without an expiry for existing embedded callers.
         *
         * @param assignmentId stable assignment identifier
         * @param principalId grantee principal
         * @param templateId exact template identifier
         * @param templateVersion exact template version
         * @param scope non-wildcard realm and optional subscopes
         * @param enabled whether the assignment participates in authorization
         */
        public Assignment(String assignmentId, String principalId, String templateId,
                int templateVersion, Permission.Scope scope, boolean enabled) {
            this(assignmentId, principalId, templateId, templateVersion, scope, java.util.Optional.empty(), enabled);
        }
    }

    private final List<Template> templates;

    private RoleTemplateCatalog(List<Template> templates) {
        this.templates = List.copyOf(templates);
    }

    /**
     * Loads the built-in strict resource through the supplied class loader.
     *
     * @param loader class loader owning server resources
     * @return immutable deterministic catalog
     */
    public static RoleTemplateCatalog load(ClassLoader loader) {
        Objects.requireNonNull(loader, "loader");
        try (InputStream input = Objects.requireNonNull(loader.getResourceAsStream(RESOURCE),
                "Built-in role-template resource is missing")) {
            byte[] encoded = input.readNBytes(MAXIMUM_RESOURCE_BYTES + 1);
            if (encoded.length > MAXIMUM_RESOURCE_BYTES) {
                throw new IllegalArgumentException("Role-template resource exceeds its technical bound");
            }
            return parse(encoded);
        } catch (IOException failure) {
            throw new IllegalStateException("Role-template resource cannot be read", failure);
        }
    }

    /**
     * Parses one complete strict versioned resource.
     *
     * @param encoded bounded UTF-8 JSON document
     * @return immutable deterministic catalog
     */
    public static RoleTemplateCatalog parse(byte[] encoded) {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length == 0 || encoded.length > MAXIMUM_RESOURCE_BYTES) {
            throw new IllegalArgumentException("Role-template resource size is invalid");
        }
        try (JsonParser parser = JSON.createParser(ObjectReadContext.empty(), encoded)) {
            require(parser.nextToken(), JsonToken.START_OBJECT);
            Integer schema = null;
            List<Template> result = null;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                require(parser.currentToken(), JsonToken.PROPERTY_NAME);
                String field = parser.currentName();
                parser.nextToken();
                if ("schemaVersion".equals(field) && schema == null) schema = parser.getIntValue();
                else if ("roles".equals(field) && result == null) result = readTemplates(parser);
                else throw new IllegalArgumentException("Unknown or duplicate role-template field");
            }
            if (parser.nextToken() != null || !Integer.valueOf(1).equals(schema) || result == null) {
                throw new IllegalArgumentException("Role-template resource framing is invalid");
            }
            result.sort(Comparator.comparing(Template::templateId));
            Set<String> ids = new HashSet<>();
            if (result.size() != 15 || result.stream().anyMatch(item -> !ids.add(item.templateId()))) {
                throw new IllegalArgumentException("Role-template set is incomplete or ambiguous");
            }
            return new RoleTemplateCatalog(result);
        } catch (IOException | RuntimeException failure) {
            if (failure instanceof IllegalArgumentException invalid) throw invalid;
            throw new IllegalArgumentException("Role-template resource is malformed");
        }
    }

    /**
     * Returns the built-in templates.
     *
     * @return immutable templates ordered by stable ID
     */
    public List<Template> templates() {
        return templates;
    }

    /**
     * Resolves one exact template.
     *
     * @param templateId stable template identifier
     * @param version exact positive template version
     * @return matching immutable template
     */
    public Template require(String templateId, int version) {
        return templates.stream().filter(item -> item.templateId().equals(templateId) && item.version() == version)
                .findFirst().orElseThrow(() -> new IllegalArgumentException("Role template is unavailable"));
    }

    /**
     * Expands one enabled scoped assignment to explicit immutable grants.
     *
     * @param assignment persisted assignment
     * @return deterministic finite grants, or an empty list when disabled
     */
    public List<Permission.Grant> instantiate(Assignment assignment) {
        Assignment exact = Objects.requireNonNull(assignment, "assignment");
        if (!exact.enabled()) return List.of();
        Template template = require(exact.templateId(), exact.templateVersion());
        return template.actions().stream().sorted(Comparator.comparingInt(Permission.Action::code))
                .flatMap(action -> {
                    Permission.Grant ordinary = new Permission.Grant(exact.assignmentId() + ":" + action.code(), exact.principalId(),
                        Permission.Effect.ALLOW, action, resourceType(action), exact.scope(),
                        relationship(template, action), dataView(action), Set.of(), exact.expiresAt(), true);
                    if (action == Permission.Action.REQUEST_READ_ANY || action == Permission.Action.REQUEST_APPROVE || action == Permission.Action.REQUEST_REJECT) {
                        Permission.Grant enrollment = new Permission.Grant(exact.assignmentId() + ":enrollment:" + action.code(), exact.principalId(),
                                Permission.Effect.ALLOW, action, Permission.ResourceType.ENROLLMENT_REQUEST, exact.scope(),
                                relationship(template, action), dataView(action), Set.of(), exact.expiresAt(), true);
                        return java.util.stream.Stream.of(ordinary, enrollment);
                    }
                    return java.util.stream.Stream.of(ordinary);
                })
                .toList();
    }

    private static Permission.ResourceType resourceType(Permission.Action action) {
        String name = action.name();
        if (name.startsWith("AUTHORITY")) return Permission.ResourceType.AUTHORITY;
        if (name.startsWith("ISSUER") || name.startsWith("CA_CHAIN")) return Permission.ResourceType.ISSUER;
        if (name.startsWith("PROFILE")) return Permission.ResourceType.PROFILE;
        if (name.startsWith("POLICY")) return Permission.ResourceType.POLICY;
        if (name.startsWith("X509_BINDING")) return Permission.ResourceType.X509_BINDING;
        if (name.startsWith("REQUEST")) return Permission.ResourceType.REQUEST;
        if (name.startsWith("CERTIFICATE")) return Permission.ResourceType.CERTIFICATE;
        if (name.startsWith("REVOCATION")) return Permission.ResourceType.REVOCATION;
        if (name.startsWith("CRL") || name.startsWith("OCSP")) return Permission.ResourceType.STATUS_OBJECT;
        if (name.startsWith("PUBLICATION")) return Permission.ResourceType.PUBLICATION;
        if (name.startsWith("AUDIT")) return Permission.ResourceType.AUDIT;
        if (name.startsWith("BACKUP")) return Permission.ResourceType.BACKUP;
        if (name.startsWith("RESTORE")) return Permission.ResourceType.RESTORE;
        if (name.startsWith("DISCLOSURE_CAPABILITY")) return Permission.ResourceType.CAPABILITY;
        if (name.startsWith("DISCLOSURE")) return Permission.ResourceType.DISCLOSURE;
        if (name.startsWith("PRINCIPAL")) return Permission.ResourceType.PRINCIPAL;
        if (name.startsWith("ROLE")) return Permission.ResourceType.ROLE;
        if (name.startsWith("PERMISSION")) return Permission.ResourceType.GRANT;
        if (name.startsWith("SERVER_CONFIGURATION")) return Permission.ResourceType.SERVER_CONFIGURATION;
        return Permission.ResourceType.REALM;
    }

    private static Permission.Relationship relationship(Template template, Permission.Action action) {
        boolean requesterCredential = "requester".equals(template.templateId())
                && action.name().startsWith("CERTIFICATE_")
                && action != Permission.Action.CERTIFICATE_CONFIRM;
        return action.name().endsWith("_OWN") || requesterCredential
                ? Permission.Relationship.OWN : Permission.Relationship.ANY;
    }

    private static Permission.DataView dataView(Permission.Action action) {
        if (action == Permission.Action.CERTIFICATE_READ_CONTENT || action == Permission.Action.CERTIFICATE_DOWNLOAD
                || action == Permission.Action.CA_CHAIN_DOWNLOAD || action == Permission.Action.CRL_DOWNLOAD) {
            return Permission.DataView.CONTENT_FULL;
        }
        if (action == Permission.Action.CERTIFICATE_READ_PII || action == Permission.Action.AUDIT_READ_PII) {
            return Permission.DataView.PII_FULL;
        }
        if (action == Permission.Action.AUDIT_READ_FULL) return Permission.DataView.METADATA_FULL;
        return Permission.DataView.METADATA_REDACTED;
    }

    private static List<Template> readTemplates(JsonParser parser) throws IOException {
        require(parser.currentToken(), JsonToken.START_ARRAY);
        List<Template> result = new ArrayList<>();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            require(parser.currentToken(), JsonToken.START_OBJECT);
            String id = null;
            Integer version = null;
            Set<Permission.Action> actions = null;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                require(parser.currentToken(), JsonToken.PROPERTY_NAME);
                String field = parser.currentName();
                parser.nextToken();
                if ("id".equals(field) && id == null) id = parser.getString();
                else if ("version".equals(field) && version == null) version = parser.getIntValue();
                else if ("actions".equals(field) && actions == null) actions = readActions(parser);
                else throw new IllegalArgumentException("Unknown or duplicate role field");
            }
            if (id == null || version == null || actions == null) throw new IllegalArgumentException("Role incomplete");
            result.add(new Template(id, version, actions));
        }
        return result;
    }

    private static Set<Permission.Action> readActions(JsonParser parser) throws IOException {
        require(parser.currentToken(), JsonToken.START_ARRAY);
        Set<Permission.Action> result = new HashSet<>();
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            require(parser.currentToken(), JsonToken.VALUE_STRING);
            Permission.Action action = Permission.Action.valueOf(parser.getString());
            if (!result.add(action)) throw new IllegalArgumentException("Duplicate role action");
        }
        return result;
    }

    private static void require(JsonToken actual, JsonToken expected) {
        if (actual != expected) throw new IllegalArgumentException("Unexpected role-template token");
    }
}
