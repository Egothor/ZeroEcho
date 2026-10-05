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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import zeroecho.pki.server.schema.OperationDescriptorCatalog;
import zeroecho.pki.server.schema.OperationParameterSchema.FieldSpec;

class OpenApiCatalogParityTest {
    @TempDir Path temporary;

    @Test void generatedOperationsPreserveEveryCatalogFieldPermissionAndAvailability() throws Exception {
        Path output = temporary.resolve("openapi.yaml");
        OpenApiGenerator.main(new String[]{"test", "src/main/resources/openapi-supplement.yaml", output.toString()});
        String yaml = Files.readString(output);
        Set<String> paths = new HashSet<>();
        Matcher path = Pattern.compile("(?m)^  '/operations/([a-z][a-z0-9.-]+)':$").matcher(yaml);
        while (path.find()) assertTrue(paths.add(path.group(1)));
        Set<String> expectedIds = new HashSet<>();
        for (OperationDescriptorCatalog.Entry entry : OperationDescriptorCatalog.current().entries()) {
            String id = entry.security().operationId();
            expectedIds.add(id);
            String endpoint = block(yaml, "  '/operations/" + id + "':", 2);
            assertTrue(endpoint.contains("x-zeroecho-available: " + entry.available()), id);
            assertTrue(endpoint.contains("x-zeroecho-permission-action: \"" + entry.security().action().name() + "\""), id);
            assertTrue(endpoint.contains("x-zeroecho-resource-type: \"" + entry.security().resourceType().name() + "\""), id);
            StringBuilder name = new StringBuilder();
            for (String part : id.split("[.-]")) name.append(Character.toUpperCase(part.charAt(0))).append(part.substring(1));
            String arguments = block(yaml, "    " + name + "Arguments:", 4);
            Set<String> actualFields = new HashSet<>();
            Matcher fieldNames = Pattern.compile("(?m)^        ([A-Za-z][A-Za-z0-9]*):$").matcher(arguments);
            while (fieldNames.find()) actualFields.add(fieldNames.group(1));
            Set<String> expectedFields = new HashSet<>();
            Set<String> required = new HashSet<>();
            Matcher requiredNames = Pattern.compile("(?m)^        - \"([^\"]+)\"$").matcher(arguments);
            while (requiredNames.find()) required.add(requiredNames.group(1));
            Set<String> expectedRequired = new HashSet<>();
            for (FieldSpec field : entry.parameters().fields()) {
                expectedFields.add(field.name());
                if (field.required()) expectedRequired.add(field.name());
                String fieldYaml = block(arguments, "        " + field.name() + ":", 8);
                String type = switch (field.type()) {
                    case TEXT, ENUM, BASE64 -> "string";
                    case BOOLEAN -> "boolean";
                    case INTEGER -> "integer";
                    case OBJECT -> "object";
                    case TEXT_SET, ENUM_SET -> "array";
                };
                assertTrue(fieldYaml.contains("          type: " + type), id + "." + field.name());
                Set<String> choices = new HashSet<>();
                Matcher values = Pattern.compile("(?m)^\\s+- \"([^\"]+)\"$").matcher(fieldYaml);
                while (values.find()) choices.add(values.group(1));
                assertEquals(Set.copyOf(field.choices()), choices, id + "." + field.name());
            }
            assertEquals(expectedFields, actualFields, id);
            assertEquals(expectedRequired, required, id);
            if (expectedFields.isEmpty()) assertTrue(arguments.contains("properties: {}"), id);
        }
        assertEquals(expectedIds, paths);
    }

    private static String block(String text, String heading, int indent) {
        int start = text.indexOf(heading + "\n");
        assertTrue(start >= 0, heading);
        int end = text.length();
        Matcher next = Pattern.compile("(?m)^ {0," + indent + "}\\S").matcher(text);
        if (next.find(start + heading.length() + 1)) end = next.start();
        return text.substring(start, end);
    }
}
