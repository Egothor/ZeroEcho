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
package zeroecho.pki.server.schema;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.OperationSecurityDescriptors.Descriptor;
import zeroecho.pki.server.ServerControlOperation;
import zeroecho.pki.server.schema.OperationParameterSchema.FieldSpec;
import zeroecho.pki.server.schema.OperationParameterSchema.FieldType;
import zeroecho.pki.server.schema.OperationParameterSchema.OperationSpec;
import zeroecho.pki.server.schema.OperationParameterSchemas.Parameters;

/**
 * Immutable, validated authority for static operation projections.
 * Execution authorization, resource binding and dynamic approvals remain in the gateway.
 * Assembly costs O(N log N + F) time and O(N + F) retained space for N operations and F fields.
 */
public final class OperationDescriptorCatalog {

    private final Map<String, Entry> entries;
    private final List<Entry> ordered;
    /** Request-affecting field refinements and optional display hints.
     * @param type client semantic type compatible with the wire type
     * @param ref existing-entity reference kind, or empty
     * @param allowNew whether external new references may be entered
     * @param hidden whether the field is managed by the client
     * @param readOnly whether the editor prohibits direct edits
     * @param label optional display label
     * @param help optional descriptive help
     * @param placeholder optional example text
     */
    public record FieldSemantics(String type, String ref, boolean allowNew, boolean hidden, boolean readOnly,
            String label, String help, String placeholder) {
        /** Rejects null semantics. */
        public FieldSemantics {
            Objects.requireNonNull(type, "type"); Objects.requireNonNull(ref, "ref");
            Objects.requireNonNull(label, "label"); Objects.requireNonNull(help, "help");
            Objects.requireNonNull(placeholder, "placeholder");
        }
    }

    /** Request-envelope and field semantics.
     * @param scope realm or authority
     * @param authorityFrom argument supplying authority, or empty
     * @param fields immutable semantic refinements keyed by argument name
     */
    public record TransportSemantics(String scope, String authorityFrom, Map<String, FieldSemantics> fields) {
        /** Validates scope and snapshots all refinements. */
        public TransportSemantics {
            if (!Set.of("realm", "authority").contains(scope)) { throw new IllegalArgumentException("Invalid operation scope"); }
            Objects.requireNonNull(authorityFrom, "authorityFrom");
            fields = Map.copyOf(fields);
        }
    }

    /** Presentation joined to a canonical operation.
     * @param operationId canonical identity
     * @param title display title
     * @param summary display summary
     * @param nav navigation area
     * @param transport request semantics
     */
    public record Presentation(String operationId, String title, String summary, String nav, TransportSemantics transport) {
        /** Rejects missing presentation values. */
        public Presentation {
            requireText(operationId); requireText(title); requireText(summary); requireText(nav);
            Objects.requireNonNull(transport, "transport");
        }
    }

    /** One fully validated operation projection.
     * @param security authoritative static permission and policy metadata
     * @param parameters compatible parameter-schema projection
     * @param presentation transport and display metadata
     * @param available whether the operation is currently executable
     */
    public record Entry(Descriptor security, OperationSpec parameters, Presentation presentation, boolean available) { }

    /** Lazy holder avoids catalog assembly until the first consumer requests it. */
    private static final class Current {
        private static final OperationDescriptorCatalog INSTANCE = new OperationDescriptorCatalog(
                OperationSecurityDescriptors.definitions(), OperationParameterSchemas.definitions(),
                OperationPresentationDefinitions.definitions());
    }

    /**
     * Assembles an exact join, rejecting missing, duplicate and unknown definitions.
     * Security definitions supply the canonical typed-operation identities.
     * @param security typed identity and security definitions
     * @param parameters parameter definitions without duplicated permissions
     * @param presentation presentation definitions
     * @throws IllegalArgumentException if coverage or field semantics disagree
     */
    public OperationDescriptorCatalog(List<Descriptor> security, List<Parameters> parameters,
            List<Presentation> presentation) {
        Map<String, Descriptor> permissions = new TreeMap<>();
        for (Descriptor descriptor : security) {
            if (permissions.putIfAbsent(descriptor.operationId(), descriptor) != null) { throw invalid("duplicate security"); }
        }
        Map<String, Parameters> arguments = new LinkedHashMap<>();
        for (Parameters definition : parameters) {
            if (arguments.putIfAbsent(definition.operationId(), definition) != null) { throw invalid("duplicate parameters"); }
        }
        Map<String, Presentation> views = new LinkedHashMap<>();
        for (Presentation definition : presentation) {
            if (views.putIfAbsent(definition.operationId(), definition) != null) { throw invalid("duplicate presentation"); }
        }
        if (!permissions.keySet().equals(arguments.keySet()) || !permissions.keySet().equals(views.keySet())) {
            throw invalid("operation identity coverage");
        }
        Map<String, Entry> joined = new LinkedHashMap<>();
        for (Map.Entry<String, Descriptor> permission : permissions.entrySet()) {
            String id = permission.getKey();
            joined.put(id, join(permission.getValue(), arguments.get(id), views.get(id)));
        }
        entries = java.util.Collections.unmodifiableMap(joined);
        ordered = List.copyOf(joined.values());
    }

    private static Entry join(Descriptor descriptor, Parameters definition, Presentation view) {
        String id = descriptor.operationId();
        Set<String> names = new HashSet<>();
        Map<String, FieldSemantics> semantics = new LinkedHashMap<>();
        for (FieldSpec field : definition.fields()) {
            validateField(field, names);
            FieldSemantics semantic = view.transport().fields().getOrDefault(field.name(), defaults(field.type()));
            if (!compatible(field.type(), semantic.type())) {
                throw invalid("field semantic type: " + id + "." + field.name());
            }
            semantics.put(field.name(), semantic);
        }
        if (!names.containsAll(view.transport().fields().keySet())) {
            throw invalid("unknown presentation field");
        }
        validateAuthority(definition, view, names, semantics);
        Presentation resolved = new Presentation(id, view.title(), view.summary(), view.nav(),
                new TransportSemantics(view.transport().scope(), view.transport().authorityFrom(), semantics));
        OperationSpec schema = new OperationSpec(id, descriptor.action().name(), descriptor.resourceType().name(), definition.fields());
        return new Entry(descriptor, schema, resolved, !ServerControlOperation.ExecuteRestore.NAME.equals(id));
    }

    private static void validateField(FieldSpec field, Set<String> names) {
        requireText(field.name());
        Objects.requireNonNull(field.type(), "field type");
        if (!names.add(field.name())) { throw invalid("duplicate field"); }
        boolean enumeration = field.type() == FieldType.ENUM || field.type() == FieldType.ENUM_SET;
        if (enumeration == field.choices().isEmpty() || new HashSet<>(field.choices()).size() != field.choices().size()
                || field.choices().stream().anyMatch(String::isBlank)) { throw invalid("field choices"); }
    }

    private static void validateAuthority(Parameters definition, Presentation view, Set<String> names,
            Map<String, FieldSemantics> semantics) {
        String authority = view.transport().authorityFrom();
        if (authority.isEmpty()) { return; }
        if (!"authority".equals(view.transport().scope()) || !names.contains(authority)) {
            throw invalid("authority source");
        }
        FieldSpec field = definition.fields().stream().filter(item -> item.name().equals(authority)).findFirst().orElseThrow();
        if (!field.required() || field.type() != FieldType.TEXT
                || !Set.of("text", "pkiId").contains(semantics.get(authority).type())) { throw invalid("authority source type"); }
    }

    /** Returns the lazily assembled current catalog.
     * @return immutable singleton
     */
    public static OperationDescriptorCatalog current() { return Current.INSTANCE; }

    /** Returns every operation, including unavailable identities, in lexical order.
     * @return immutable ordered entries
     */
    public List<Entry> entries() { return ordered; }

    /** Looks up a canonical identity without filling custom registries.
     * @param operationId exact identity
     * @return matching entry, or empty
     */
    public Optional<Entry> find(String operationId) { return Optional.ofNullable(entries.get(operationId)); }

    /** Requires a known canonical identity.
     * @param operationId exact identity
     * @return immutable entry
     * @throws IllegalArgumentException if unknown
     */
    public Entry require(String operationId) { return find(operationId).orElseThrow(() -> invalid("unknown operation")); }

    /** Returns unchanged security-record projections.
     * @return immutable security list
     */
    public List<Descriptor> securityDescriptors() { return ordered.stream().map(Entry::security).toList(); }

    /** Returns unchanged four-component parameter-record projections.
     * @return immutable complete schema list
     */
    public List<OperationSpec> parameterSchemas() { return ordered.stream().map(Entry::parameters).toList(); }

    private static void requireText(String value) {
        if (value == null || value.isBlank()) { throw invalid("blank definition"); }
    }
    private static IllegalArgumentException invalid(String reason) { return new IllegalArgumentException("Invalid operation catalog: " + reason); }
    private static FieldSemantics defaults(FieldType type) {
        String semantic = switch (type) {
            case TEXT -> "text"; case INTEGER -> "integer"; case BOOLEAN -> "boolean";
            case TEXT_SET -> "stringSet"; case ENUM -> "enum"; case ENUM_SET -> "enumSet";
            case BASE64 -> "base64"; case OBJECT -> "json";
        };
        return new FieldSemantics(semantic, "", false, false, false, "", "", "");
    }
    private static boolean compatible(FieldType wire, String semantic) {
        return switch (wire) {
            case TEXT -> Set.of("text", "pkiId", "instant").contains(semantic);
            case INTEGER -> Set.of("integer", "long").contains(semantic);
            default -> defaults(wire).type().equals(semantic);
        };
    }
}
