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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import tools.jackson.core.JsonParser;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.JsonToken;
import tools.jackson.core.json.JsonFactory;
import zeroecho.pki.application.PkiOperation;
import zeroecho.pki.application.PkiSigningOperation;
import zeroecho.pki.server.OperationSecurityDescriptors;
import zeroecho.pki.server.ServerControlOperation;
import zeroecho.pki.server.schema.OperationDescriptorCatalog.Presentation;
import zeroecho.pki.server.schema.OperationDescriptorCatalog.TransportSemantics;
import zeroecho.pki.server.schema.OperationParameterSchemas.Parameters;

class OperationDescriptorCatalogTest {
    @Test void exactCoverageOfAllThreeSealedFamiliesAndAllProjections() throws Exception {
        Set<String> typed = new HashSet<>();
        OperationDescriptorCatalog catalog = OperationDescriptorCatalog.current();
        Map<Class<?>, OperationSecurityDescriptors.Family> families = Map.of(
                PkiOperation.class, OperationSecurityDescriptors.Family.PKI_OPERATION,
                PkiSigningOperation.class, OperationSecurityDescriptors.Family.SIGNING_OPERATION,
                ServerControlOperation.class, OperationSecurityDescriptors.Family.SERVER_CONTROL_OPERATION);
        for (Map.Entry<Class<?>, OperationSecurityDescriptors.Family> family : families.entrySet()) {
            Set<String> identities = new HashSet<>();
            collect(family.getKey(), identities);
            for (String identity : identities) {
                assertTrue(typed.add(identity));
                assertEquals(family.getValue(), catalog.require(identity).security().family(), identity);
            }
        }
        assertEquals(typed, catalog.entries().stream().map(entry -> entry.security().operationId()).collect(java.util.stream.Collectors.toSet()));
        assertEquals(typed, new OperationSecurityDescriptors().descriptors().keySet());
        assertEquals(typed, OperationParameterSchemas.all().stream().map(OperationParameterSchema.OperationSpec::operationId).collect(java.util.stream.Collectors.toSet()));
        List<?> projection;
        try (JsonParser parser = new JsonFactory().createParser(ObjectReadContext.empty(), GenerateOperationSchema.serialize(catalog.parameterSchemas()))) {
            parser.nextToken();
            projection = (List<?>) json(parser);
        }
        Set<String> generated = new HashSet<>();
        for (Object node : projection) {
            Map<?, ?> item = (Map<?, ?>) node;
            String id = (String) item.get("operationId");
            assertTrue(generated.add(id));
            OperationDescriptorCatalog.Entry entry = catalog.require(id);
            assertEquals(entry.security().action().name(), item.get("permissionAction"));
            assertEquals(entry.security().resourceType().name(), item.get("permissionResourceType"));
            assertEquals(entry.available(), item.get("available"));
            List<?> fields = (List<?>) item.get("fields");
            assertEquals(entry.parameters().fields().size(), fields.size());
            for (int index = 0; index < entry.parameters().fields().size(); index++) {
                OperationParameterSchema.FieldSpec field = entry.parameters().fields().get(index);
                Map<?, ?> value = (Map<?, ?>) fields.get(index);
                assertEquals(field.name(), value.get("name"));
                assertEquals(field.required(), value.get("required"));
                assertEquals(field.type().name().toLowerCase(java.util.Locale.ROOT).replace('_', '-'), value.get("type"));
                assertEquals(field.choices(), value.get("choices"));
            }
        }
        assertEquals(typed, generated);
        assertTrue(typed.containsAll(Set.of("backup.export", "backup.verify", "backup.restore", "inventory.status")));
        assertFalse(typed.contains("status.list"));
        assertFalse(catalog.require("backup.restore").available());
    }

    @Test void incompleteDuplicateUnknownAndInvalidFieldDefinitionsFailClosed() {
        List<OperationSecurityDescriptors.Descriptor> security = OperationSecurityDescriptors.definitions();
        List<Parameters> parameters = OperationParameterSchemas.definitions();
        List<Presentation> views = OperationPresentationDefinitions.definitions();
        assertThrows(IllegalArgumentException.class, () -> new OperationDescriptorCatalog(security, parameters.subList(1, parameters.size()), views));
        assertThrows(IllegalArgumentException.class, () -> new OperationDescriptorCatalog(security, parameters, views.subList(1, views.size())));
        List<Parameters> duplicate = new ArrayList<>(parameters); duplicate.add(parameters.getFirst());
        assertThrows(IllegalArgumentException.class, () -> new OperationDescriptorCatalog(security, duplicate, views));
        List<Parameters> unknown = new ArrayList<>(parameters); unknown.add(new Parameters("unknown.operation", List.of()));
        assertThrows(IllegalArgumentException.class, () -> new OperationDescriptorCatalog(security, unknown, views));
        List<Parameters> badField = parameters.stream().map(value -> value.operationId().equals("ca.inspect")
                ? new Parameters(value.operationId(), List.of(OperationParameterSchema.FieldSpec.integer("caId", true))) : value).toList();
        assertThrows(IllegalArgumentException.class, () -> new OperationDescriptorCatalog(security, badField, views));
        List<Parameters> optionalAuthority = parameters.stream().map(value -> value.operationId().equals("ca.inspect")
                ? new Parameters(value.operationId(), List.of(OperationParameterSchema.FieldSpec.text("caId", false))) : value).toList();
        assertThrows(IllegalArgumentException.class, () -> new OperationDescriptorCatalog(security, optionalAuthority, views));
        List<Presentation> badAuthority = views.stream().map(value -> value.operationId().equals("ca.inspect")
                ? new Presentation(value.operationId(), value.title(), value.summary(), value.nav(),
                        new TransportSemantics("authority", "absent", Map.of())) : value).toList();
        assertThrows(IllegalArgumentException.class, () -> new OperationDescriptorCatalog(security, parameters, badAuthority));
    }

    @Test void customSecuritySubsetRetainsItsOwnPolicyAndFamily() {
        OperationSecurityDescriptors.Descriptor original = OperationDescriptorCatalog.current().require("ca.inspect").security();
        OperationSecurityDescriptors.Descriptor custom = new OperationSecurityDescriptors.Descriptor(original.operationId(),
                OperationSecurityDescriptors.Family.SERVER_CONTROL_OPERATION, original.action(), original.resourceType(),
                true, original.dataView(), OperationSecurityDescriptors.ApprovalCategory.HIGH_RISK, original.eligibility());
        OperationSecurityDescriptors descriptors = new OperationSecurityDescriptors(List.of(custom));
        assertEquals(Map.of("ca.inspect", custom), descriptors.descriptors());
        assertEquals(custom, descriptors.require("ca.inspect"));
        assertThrows(SecurityException.class, () -> descriptors.require("backup.restore"));
        assertTrue(descriptors.require("ca.inspect").available());
    }

    private static void collect(Class<?> type, Set<String> names) throws ReflectiveOperationException {
        for (Class<?> child : type.getPermittedSubclasses()) {
            if (child.isSealed()) collect(child, names);
            for (Field field : child.getDeclaredFields()) {
                if (field.getType() == String.class && Modifier.isStatic(field.getModifiers()) && Modifier.isFinal(field.getModifiers())) {
                    String value = (String) field.get(null);
                    if (value.matches("[a-z][a-z0-9.-]+[.][a-z0-9.-]+")) assertTrue(names.add(value), value);
                }
            }
        }
    }

    private static Object json(JsonParser parser) throws java.io.IOException {
        return switch (parser.currentToken()) {
            case START_ARRAY -> {
                List<Object> values = new ArrayList<>();
                while (parser.nextToken() != JsonToken.END_ARRAY) values.add(json(parser));
                yield values;
            }
            case START_OBJECT -> {
                Map<String, Object> values = new java.util.LinkedHashMap<>();
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    String name = parser.currentName();
                    parser.nextToken();
                    values.put(name, json(parser));
                }
                yield values;
            }
            case VALUE_STRING -> parser.getString();
            case VALUE_TRUE -> true;
            case VALUE_FALSE -> false;
            default -> throw new java.io.IOException("Unexpected generated JSON token");
        };
    }
}
