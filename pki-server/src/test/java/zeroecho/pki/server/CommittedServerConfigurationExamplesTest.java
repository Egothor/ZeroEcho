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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/** Validates runnable examples without opening listeners, providers, or stores. */
class CommittedServerConfigurationExamplesTest {
    private static final Pattern JSON_FENCE = Pattern.compile(
            "(?m)^ *```json[^\\r\\n]*\\R(.*?)^ *``` *$", Pattern.DOTALL);
    private static final Pattern JSON_KEY = Pattern.compile(
            "^( *)([A-Za-z0-9_.-]+\\.json): *(.*)$");
    private static final Pattern SERVER_NAME = Pattern.compile("\\\"serverName\\\"\\s*:");

    @TestFactory
    Stream<DynamicTest> decodesEveryMaintainedServerExample() throws IOException {
        Path repository = Path.of(System.getProperty("configurationExamples.repository"));
        List<Example> examples = new ArrayList<>();
        for (String directory : List.of("docs", "documentation", "deploy")) {
            Path root = repository.resolve(directory);
            assertTrue(Files.isDirectory(root), "Missing maintained example directory: " + directory);
            try (Stream<Path> paths = Files.walk(root)) {
                for (Path path : paths.filter(Files::isRegularFile).sorted().toList()) {
                    if (path.startsWith(repository.resolve("docs/codex"))) {
                        continue;
                    }
                    String relative = repository.relativize(path).toString();
                    String name = path.getFileName().toString();
                    if (name.endsWith(".json")) {
                        String text = Files.readString(path);
                        if (isServerDocument(text) || name.startsWith("pki-server-")
                                || name.equals("server-config.json")) {
                            examples.add(new Example(relative, text, "json"));
                        }
                    } else if (name.endsWith(".yaml") || name.endsWith(".yml")) {
                        examples.addAll(yamlExamples(relative, Files.readString(path)));
                    } else if (name.endsWith(".md")) {
                        Matcher fences = JSON_FENCE.matcher(Files.readString(path));
                        int index = 0;
                        while (fences.find()) {
                            index++;
                            if (isServerDocument(fences.group(1))) {
                                examples.add(new Example(relative + "#json-" + index, fences.group(1), "md"));
                            }
                        }
                    }
                }
            }
        }
        // Fail closed if a discovery category disappears or its extractor stops finding fixtures.
        assertTrue(examples.stream().filter(example -> example.format().equals("json")).count() >= 4,
                "Expected the four shipped JSON server configurations");
        assertTrue(examples.stream().anyMatch(example -> example.format().equals("yaml")),
                "Expected a Kubernetes server ConfigMap example");
        assertTrue(examples.stream().anyMatch(example -> example.format().equals("md")),
                "Expected a complete configuration reference example");
        return examples.stream().map(example -> DynamicTest.dynamicTest(example.location(), () -> {
            PkiServerConfiguration configuration = PkiServerConfigurationCodec.decode(
                    example.document().getBytes(StandardCharsets.UTF_8));
            assertEquals(PkiServerConfiguration.CURRENT_VERSION, configuration.version());
        }));
    }

    @Test
    void yamlExtractionRespectsBlockBoundariesAndRejectsUnsupportedServerEncoding() {
        List<Example> examples = yamlExamples("fixture.yaml", """
                data:
                  server-config.json: |
                    {"serverName":"fixture"}
                  other.json: |
                    {"unrelated":true}
                ---
                kind: Secret
                """);
        assertEquals(1, examples.size());
        assertEquals("{\"serverName\":\"fixture\"}\n", examples.getFirst().document());
        assertThrows(AssertionError.class, () -> yamlExamples("fixture.yaml", """
                data:
                  server-config.json: >
                    {"serverName":"fixture"}
                """));
        assertThrows(AssertionError.class, () -> yamlExamples("fixture.yaml", """
                data:
                  server-config.json: |
                  other: value
                """));
    }

    @Test
    void currentVersionAuthorityAlsoRejectsFutureVersion() throws IOException {
        Path repository = Path.of(System.getProperty("configurationExamples.repository"));
        String document = Files.readString(repository.resolve("docs/pki-server-production-example.json"));
        String future = document.replaceFirst("\"version\"\\s*:\\s*\\d+",
                "\"version\": " + (PkiServerConfiguration.CURRENT_VERSION + 1));
        assertFalse(document.equals(future));
        assertThrows(IllegalArgumentException.class,
                () -> PkiServerConfigurationCodec.decode(future.getBytes(StandardCharsets.UTF_8)));
    }

    // Maintained Kubernetes manifests use literal JSON block scalars. This is intentionally
    // not a general YAML parser: fail when a server payload uses another representation.
    private static List<Example> yamlExamples(String location, String yaml) {
        List<Example> result = new ArrayList<>();
        List<String> lines = yaml.lines().toList();
        for (int index = 0; index < lines.size(); index++) {
            Matcher key = JSON_KEY.matcher(lines.get(index));
            if (!key.matches()) {
                continue;
            }
            boolean serverKey = key.group(2).equals("server-config.json")
                    || key.group(2).startsWith("pki-server-");
            if (serverKey) {
                assertTrue(key.group(3).matches("\\|[-+]?"),
                        location + ": server configuration must use a literal JSON block");
            }
            if (!key.group(3).matches("\\|[-+]?")) {
                continue;
            }
            int keyIndent = key.group(1).length();
            StringBuilder block = new StringBuilder();
            int contentIndent = -1;
            while (index + 1 < lines.size()) {
                String line = lines.get(index + 1);
                int indent = line.length() - line.stripLeading().length();
                if (!line.isBlank() && indent <= keyIndent) {
                    break;
                }
                index++;
                if (line.isBlank()) {
                    block.append('\n');
                    continue;
                }
                if (contentIndent < 0) {
                    contentIndent = indent;
                }
                assertTrue(indent >= contentIndent, location + ": invalid JSON block indentation");
                block.append(line.substring(contentIndent)).append('\n');
            }
            String document = block.toString();
            if (serverKey || isServerDocument(document)) {
                assertFalse(document.isBlank(), location + ": empty server configuration block");
                result.add(new Example(location + "#" + key.group(2), document, "yaml"));
            }
        }
        if (isServerDocument(yaml) || yaml.contains("server-config.json:")) {
            assertFalse(result.isEmpty(), location + ": no supported server configuration block found");
        }
        return result;
    }

    private static boolean isServerDocument(String text) {
        return SERVER_NAME.matcher(text).find();
    }

    private record Example(String location, String document, String format) { }
}
